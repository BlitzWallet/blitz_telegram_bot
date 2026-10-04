import { randomBytes } from 'node:crypto';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { hashPin, randomId, verifyPin } from './crypto.js';
import {
  decodeInvoice,
  findInvoice,
  InvoiceError,
  isValidPreimage,
} from './invoice.js';
import {
  ConnectionStringError,
  containsConnectionString,
  NwcTimeoutError,
  parseConnectionString,
} from './nwc.js';

const MIN = 60_000;
export const LIMITS = {
  confirmTtlMs: 2 * MIN,
  payExpiresInSec: 60, // `expiration` tag on pay_invoice; wallets ignore it after this
  payTimeoutMs: 70_000,
  readExpiresInSec: 45,
  readTimeoutMs: 45_000,
  notFoundGraceMs: 2 * MIN, // after request expiration, NOT_FOUND means "never sent"
  unknownGiveUpMs: 3 * 24 * 60 * MIN,
  invoiceExpirySec: 3600,
  invoiceCheckMinutes: [1, 3, 10, 30],
  maxOpenInvoices: 5,
  maxReceiveSats: 100_000_000,
  txPageSize: 10,
  txMaxPages: 20,
  pinLength: 6,
  pinMaxFailures: 5,
  pinLockMs: 60 * MIN,
  pinSessionMs: 5 * MIN,
  retentionMs: 7 * 24 * 60 * MIN,
  maxConcurrentWalletCalls: 100,
  pairingTimeoutMs: 15 * MIN,
  maxPendingPairings: 1000,
};

const PAIRING_URL = 'https://blitzwallet.app/nwc/auth';
// Telegram buttons can only open http(s) links and copy at most 256
// characters, so "Open wallet" / long "Copy" go through this page, which takes
// the invoice from the #fragment (never sent to the server). Source:
// blitz-wallet-website/pages/pay/index.html
const PAY_PAGE_URL = 'https://blitzwalletapp.com/pay';
const INLINE_THUMBNAIL_URL =
  'https://blitzwalletapp.com/public/favicon/web-app-manifest-512x512.png';
const MAX_COPY_TEXT = 256;
// Required for the bot to work at all; sending is the user's choice in Blitz.
const PAIRING_METHODS =
  'get_info get_balance make_invoice lookup_invoice list_transactions';
const PAIRING_OPTIONAL_METHODS = 'pay_invoice';

// NIP-47 codes that mean the wallet did not (and will not) send the payment.
// Everything else — INTERNAL, OTHER, timeouts, a result without a valid
// preimage — is "unknown" and is reconciled, never retried.
const DEFINITIVE_PAY_ERRORS = new Set([
  'QUOTA_EXCEEDED',
  'INSUFFICIENT_BALANCE',
  'RESTRICTED',
  'UNAUTHORIZED',
  'RATE_LIMITED',
  'NOT_IMPLEMENTED',
  'UNSUPPORTED_ENCRYPTION',
  'PAYMENT_FAILED',
]);

const BOT_METHODS = [
  'get_balance',
  'make_invoice',
  'lookup_invoice',
  'list_transactions',
  'pay_invoice',
];

export function classifyPayResponse(response, paymentHash) {
  if (response?.result) {
    if (isValidPreimage(response.result.preimage, paymentHash)) {
      const fee = Number(response.result.fees_paid);
      return {
        status: 'paid',
        feeMsat: Number.isSafeInteger(fee) && fee >= 0 ? fee : null,
      };
    }
    return { status: 'unknown' };
  }
  if (response?.error && DEFINITIVE_PAY_ERRORS.has(response.error.code)) {
    return { status: 'failed', reason: response.error.code };
  }
  return { status: 'unknown' };
}

// Interprets lookup_invoice for an outgoing payment we sent once.
export function classifyPaymentLookup(response, payment, nowMs) {
  if (response?.result) {
    const r = response.result;
    if (r.type && r.type !== 'outgoing') return { status: 'unknown' };
    if (
      isValidPreimage(r.preimage, payment.payment_hash) ||
      r.state === 'settled'
    ) {
      const fee = Number(r.fees_paid);
      return {
        status: 'paid',
        feeMsat: Number.isSafeInteger(fee) && fee >= 0 ? fee : null,
      };
    }
    if (r.state === 'failed')
      return { status: 'failed', reason: 'PAYMENT_FAILED' };
    return { status: 'unknown' };
  }
  if (response?.error?.code === 'NOT_FOUND') {
    // The wallet records a payment before sending it. Once our request has
    // expired (plus grace for one already in progress), no record means the
    // wallet never acted on it and never will.
    const expiredAt =
      payment.request_expires_at ??
      payment.updated_at + LIMITS.payExpiresInSec * 1000;
    if (nowMs > expiredAt + LIMITS.notFoundGraceMs)
      return { status: 'failed', reason: 'NOT_SENT' };
  }
  return { status: 'unknown' };
}

const escapeHtml = s =>
  String(s).replace(
    /[&<>"]/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c],
  );
const sats = msat => Math.floor(msat / 1000).toLocaleString('en-US');
const fmtDate = sec =>
  new Date(sec * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
const minutesUntil = (ms, now) => Math.max(0, Math.round((ms - now) / MIN));
const isWeakPin = pin =>
  /^(\d)\1+$/.test(pin) ||
  '0123456789'.includes(pin) ||
  '9876543210'.includes(pin);

function bucket(capacity, perMinute) {
  return { capacity, refillPerMs: perMinute / MIN };
}
const RATE = { update: bucket(40, 30), wallet: bucket(4, 8) };

const HELP = `<b>Blitz Wallet for Telegram</b>
This bot is a remote control for the <b>Wallet Connect account</b> in your Blitz Wallet. Your money stays in Blitz; the bot never holds your funds or recovery phrase.

/balance – Wallet Connect balance
/receive <i>amount</i> [memo] – create an invoice, e.g. <code>/receive 21000 coffee</code>
/send – pay an invoice (or just paste one)
/transactions – recent activity
/status – payments and invoices the bot is tracking
/connect – connect or replace your wallet
/disconnect – remove your wallet from this bot

<b>Request money in any chat:</b> type my @username followed by an amount, e.g. <code>5000 pizza</code>, and tap the result. Only the invoice is posted; your balance stays private.

<b>Stay safe</b>
• Blitz will never ask you for your connection string or PIN in a chat.
• Only pay invoices you expected. The memo is written by whoever made the invoice.
• To revoke access instantly, delete the connection in Blitz → Settings → Wallet Connect.`;

const PASTE_HOWTO = `<b>Connect manually (older Blitz versions)</b>
1. In Blitz, open <b>Settings → Wallet Connect → Add connection</b>.
2. Name it <b>Telegram</b> (use it only for this bot).
3. Permissions: Receive payments, Get Balance, Transactions, Lookup Invoice. Add <b>Send payments</b> only if you want to pay from Telegram.
4. Set a <b>budget</b> (e.g. a daily limit). Blitz enforces it, even if this bot were compromised.
5. Copy the connection string and paste it here.

I delete the message as soon as I receive it. Telegram may still keep a copy on its servers, which is another reason to use a dedicated connection with a budget.`;

export function createBot({
  tg,
  store,
  nwc,
  keyring,
  config,
  log,
  now = () => Date.now(),
}) {
  const chains = new Map(); // userId -> promise; serializes each user's updates
  const background = new Set(); // detached payment submissions / notifications
  const pinSessions = new Map(); // userId -> keypad session (digits never persisted)
  const buckets = new Map();
  const submitting = new Set(); // payment ids owned by a live submit call
  const pairings = new Map(); // userId -> AbortController of the pending link
  let walletCalls = 0;
  let maintenanceRunning = false;

  const track = promise => {
    background.add(promise);
    promise.finally(() => background.delete(promise));
    return promise;
  };
  const safe = p => p.catch(err => log.warn('telegram call failed', { err }));
  const send = (chatId, text, extra = {}) =>
    safe(
      tg.call('sendMessage', {
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
        ...extra,
      }),
    );
  const edit = (chatId, messageId, text, extra = {}) =>
    safe(
      tg.call('editMessageText', {
        chat_id: chatId,
        message_id: messageId,
        text,
        parse_mode: 'HTML',
        ...extra,
      }),
    );

  function allow(userId, kind) {
    const spec = RATE[kind];
    const key = `${kind}:${userId}`;
    const t = now();
    const b = buckets.get(key) ?? { tokens: spec.capacity, at: t };
    b.tokens = Math.min(
      spec.capacity,
      b.tokens + (t - b.at) * spec.refillPerMs,
    );
    b.at = t;
    buckets.set(key, b);
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  const aad = (userId, walletPubkey) => `${userId}:${walletPubkey}`;
  const methodsOf = wallet => new Set(wallet.methods.split(' '));
  const connFor = wallet => ({
    walletPubkey: wallet.wallet_pubkey,
    relays: JSON.parse(wallet.relays),
    secret: keyring.decrypt(
      wallet.secret_enc,
      aad(wallet.user_id, wallet.wallet_pubkey),
    ),
    encryption: wallet.encryption,
  });

  // Every wallet round trip goes through here: global concurrency cap, and the
  // request carries an expiration so a delayed delivery is ignored by the wallet.
  async function walletCall(conn, method, params) {
    if (walletCalls >= LIMITS.maxConcurrentWalletCalls) return { busy: true };
    walletCalls++;
    try {
      return await nwc.call(conn, method, params, {
        timeoutMs: LIMITS.readTimeoutMs,
        expiresInSec: LIMITS.readExpiresInSec,
      });
    } catch (err) {
      if (err instanceof NwcTimeoutError) return { timeout: true };
      throw err;
    } finally {
      walletCalls--;
    }
  }

  const walletTrouble = r =>
    r.busy
      ? 'The bot is busy right now. Please try again in a minute.'
      : r.timeout
        ? 'Your wallet didn’t respond. Make sure Blitz has notifications enabled and the Telegram connection still exists in Settings → Wallet Connect.'
        : ['UNAUTHORIZED', 'RESTRICTED'].includes(r.error?.code)
          ? 'Your wallet refused this request. The connection may have been removed or lacks this permission. Use /connect to set it up again.'
          : 'Your wallet couldn’t complete that request. Please try again later.';

  // ------------------------------------------------------------------ updates

  // Everything that touches one user's state runs in order on that user's chain.
  function runForUser(userId, fn) {
    const prev = chains.get(userId) ?? Promise.resolve();
    const next = prev.then(fn);
    const settled = next.catch(() => {});
    chains.set(userId, settled);
    settled.finally(
      () => chains.get(userId) === settled && chains.delete(userId),
    );
    return next;
  }

  function handleUpdate(update) {
    const userId = (
      update.message ??
      update.edited_message ??
      update.callback_query ??
      update.inline_query ??
      update.chosen_inline_result
    )?.from?.id;
    if (!Number.isSafeInteger(userId)) return Promise.resolve();
    return runForUser(userId, async () => {
      try {
        await dispatch(update);
      } catch (err) {
        log.error('update handler failed', { err, user: log.user(userId) });
        const chat = (
          update.message ??
          update.edited_message ??
          update.callback_query?.message
        )?.chat;
        // Never echo the error itself; it may contain request details.
        if (chat?.type === 'private')
          await send(
            userId,
            'Something went wrong on my side. Please try again.',
          );
      }
    });
  }

  async function dispatch(update) {
    if (update.callback_query) return onCallback(update.callback_query);
    if (update.inline_query) return onInlineQuery(update.inline_query);
    if (update.chosen_inline_result) {
      return onChosenInlineResult(update.chosen_inline_result);
    }
    const msg = update.message ?? update.edited_message;
    if (!msg?.from || msg.from.is_bot) return;
    const userId = msg.from.id;
    const text = String(msg.text ?? msg.caption ?? '').slice(0, 4096);

    // Before anything else: get connection strings out of the chat, wherever
    // they appear (text, caption, or an edit).
    const hasSecret = containsConnectionString(text);
    if (hasSecret)
      await safe(
        tg.call('deleteMessage', {
          chat_id: msg.chat.id,
          message_id: msg.message_id,
        }),
      );

    if (msg.chat.type !== 'private') {
      if (hasSecret) {
        await send(
          msg.chat.id,
          '⚠️ A wallet connection string was posted here. I deleted the message, but treat it as exposed: delete that connection in Blitz → Settings → Wallet Connect.',
        );
      }
      await safe(tg.call('leaveChat', { chat_id: msg.chat.id }));
      return;
    }
    if (!allow(userId, 'update'))
      return send(userId, 'Slow down a little and try again in a minute.');
    if (config.allowedUsers && !config.allowedUsers.has(userId)) {
      return send(userId, 'This bot is private.');
    }
    // Edits and non-text messages are only screened for secrets, never executed.
    if (update.edited_message || typeof msg.text !== 'string') {
      return hasSecret ? connect(userId, text) : undefined;
    }

    if (hasSecret) return connect(userId, text);

    const [, command, args = ''] =
      text.match(/^\/([a-z_]+)(?:@\w+)?\s*([\s\S]*)$/i) ?? [];
    switch (command?.toLowerCase()) {
      case 'start':
        // Deep link from inline mode's "Connect your Blitz Wallet first".
        if (args.trim() === 'connect') return startPairing(userId);
        // From the "Pay" button on an invoice someone posted in a chat.
        if (/^pay_[A-Za-z0-9_-]{1,32}$/.test(args.trim())) {
          return payPosted(userId, args.trim().slice(4));
        }
        return send(
          userId,
          store.getWallet(userId)
            ? HELP
            : `${HELP}\n\nTo get started, use /connect.`,
        );
      case 'help':
        return send(userId, HELP);
      case 'connect':
        return startPairing(userId);
      case 'connect_manual':
        return send(userId, PASTE_HOWTO);
      case 'balance':
        return balance(userId);
      case 'receive':
        return receive(userId, args);
      case 'send':
        return args.trim()
          ? startSend(userId, args)
          : send(userId, 'Paste the Lightning invoice you want to pay.');
      case 'transactions':
        return transactions(userId, 0);
      case 'status':
        return status(userId);
      case 'disconnect':
        return askDisconnect(userId);
    }
    if (findInvoice(text)) return startSend(userId, text);
    return send(
      userId,
      'I didn’t understand that. Send /help to see what I can do.',
    );
  }

  async function onCallback(cq) {
    const userId = cq.from.id;
    const answer = text =>
      safe(
        tg.call('answerCallbackQuery', {
          callback_query_id: cq.id,
          ...(text ? { text } : {}),
        }),
      );
    const msg = cq.message;
    // Callback data is client-controlled: accept only our exact formats, and
    // every id is re-checked against the presser's own rows.
    const m = /^([a-z]{1,3}):([A-Za-z0-9_-]{1,32})(?::([0-9bx]))?$/.exec(
      cq.data ?? '',
    );
    if (m?.[1] === 'ip') return payPostedInvoice(cq, m[2], answer);
    if (!m || msg?.chat?.type !== 'private' || msg.chat.id !== userId)
      return answer();
    if (config.allowedUsers && !config.allowedUsers.has(userId))
      return answer();
    if (!allow(userId, 'update')) return answer('Slow down a little.');
    const [, action, id, key] = m;
    await answer();
    switch (action) {
      case 'k':
        return keypad(userId, msg.message_id, id, key);
      case 'pc':
        return confirmPayment(userId, msg.message_id, id);
      case 'px':
        if (store.cancelPayment(id, userId, now())) pinSessions.delete(userId);
        return edit(
          userId,
          msg.message_id,
          'Payment cancelled. Nothing was sent.',
        );
      case 'ic':
        return checkInvoice(userId, id);
      case 'tx':
        return transactions(userId, Number(id) || 0, msg.message_id);
      case 'sr':
        return refreshStatus(userId);
      case 'dc':
        return id === 'yes'
          ? disconnect(userId, msg.message_id)
          : edit(userId, msg.message_id, 'Still connected.');
    }
  }

  // ---------------------------------------------------------------- connect

  async function connect(userId, text) {
    if (!allow(userId, 'wallet'))
      return send(userId, 'Slow down a little and try again in a minute.');
    let parsed;
    try {
      parsed = parseConnectionString(text, config.allowedRelays);
    } catch (err) {
      if (!(err instanceof ConnectionStringError)) throw err;
      return send(
        userId,
        err.reason === 'relay'
          ? 'That connection uses a relay this bot doesn’t support. Please create the connection in Blitz Wallet.'
          : 'That doesn’t look like a valid Blitz Wallet connection string. Copy it again from Blitz → Settings → Wallet Connect.',
      );
    }
    if (store.inFlightPaymentCount(userId) > 0) {
      return send(
        userId,
        'A payment is still being confirmed. Please wait until it resolves (see /status) before changing your connection.',
      );
    }

    await send(
      userId,
      'Checking your wallet… (this can take a few seconds while Blitz wakes up)',
    );
    let conn;
    try {
      conn = { ...parsed, encryption: await nwc.negotiateEncryption(parsed) };
    } catch {
      return send(
        userId,
        'I couldn’t reach the wallet relay. Please try again in a minute.',
      );
    }
    const res = await walletCall(conn, 'get_info', {});
    if (!res.result)
      return send(userId, `Not connected. ${walletTrouble(res)}`);
    return saveConnection(userId, conn, res.result.methods);
  }

  // Shared by both flows. `conn.secret` is the NWC client secret; it is only
  // ever written encrypted.
  async function saveConnection(userId, conn, methods) {
    const granted = Array.isArray(methods)
      ? methods.filter(m => BOT_METHODS.includes(m))
      : [];
    if (!granted.length)
      return send(
        userId,
        'This connection doesn’t allow anything the bot can do. Enable at least Get Balance or Receive payments in Blitz and try again.',
      );

    const t = now();
    const replaced = store.getWallet(userId);
    // Confirmations and keypads belong to the old connection.
    store.cancelAwaiting(userId, t);
    pinSessions.delete(userId);
    store.upsertWallet({
      userId,
      walletPubkey: conn.walletPubkey,
      relays: conn.relays,
      secretEnc: keyring.encrypt(conn.secret, aad(userId, conn.walletPubkey)),
      encryption: conn.encryption,
      methods: granted,
      now: t,
    });
    if (replaced) store.closeOpenInvoices(userId, t);
    log.info('wallet connected', {
      user: log.user(userId),
      methods: granted.join(' '),
      replaced: !!replaced,
    });

    const can = new Set(granted);
    const lines = [
      '✅ <b>Wallet connected.</b>',
      `${can.has('get_balance') ? '✅' : '—'} Balance   ${can.has('make_invoice') ? '✅' : '—'} Receive   ${can.has('list_transactions') ? '✅' : '—'} Transactions   ${can.has('pay_invoice') && can.has('lookup_invoice') ? '✅' : '—'} Send`,
    ];
    if (can.has('pay_invoice') && !can.has('lookup_invoice')) {
      lines.push(
        'Sending is off: also enable <b>Lookup Invoice</b> so I can confirm whether a payment went through.',
      );
    }
    if (replaced && replaced.wallet_pubkey !== conn.walletPubkey) {
      lines.push(
        'Your previous connection was replaced. Delete it in Blitz → Settings → Wallet Connect so it can’t be used anymore.',
      );
    }
    await send(userId, lines.join('\n'));
    if (can.has('pay_invoice') && can.has('lookup_invoice')) {
      return startPinSession(
        userId,
        { purpose: 'set' },
        'Choose a 6-digit <b>payment PIN</b>. You’ll enter it on this keypad for every payment; it never appears in the chat.',
      );
    }
  }

  // ------------------------------------------------------- NWC-08 pairing

  // The bot generates the connection key itself and sends Blitz only the
  // public half in a link. Nothing secret is pasted, shown or sent through
  // Telegram, and the secret is kept in memory until Blitz approves.
  async function startPairing(userId) {
    if (store.inFlightPaymentCount(userId) > 0) {
      return send(
        userId,
        'A payment is still being confirmed. Please wait until it resolves (see /status) before changing your connection.',
      );
    }
    pairings.get(userId)?.abort(); // a new link replaces the previous one
    if (pairings.size >= LIMITS.maxPendingPairings) {
      return send(
        userId,
        'The bot is busy right now. Please try again in a minute.',
      );
    }

    const sk = generateSecretKey();
    const secret = bytesToHex(sk);
    const clientPubkey = getPublicKey(sk);
    const state = randomBytes(16).toString('hex');
    const relays = [config.allowedRelays[0]];
    const params = [
      ['relay', relays[0]],
      ['state', state],
      [
        'name',
        config.botUsername ? `Telegram @${config.botUsername}` : 'Telegram bot',
      ],
      ['request_methods', PAIRING_METHODS],
      ['optional_request_methods', PAIRING_OPTIONAL_METHODS],
      ...(config.connectBudgetSats
        ? [
            ['max_amount', String(config.connectBudgetSats * 1000)],
            ['renewal_period', 'daily'],
          ]
        : []),
    ]
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join('&');
    const link = `${PAIRING_URL}?pubkey=${clientPubkey}&${params}`;
    const uri = `nostr+walletauth://${clientPubkey}?${params}`;

    const abort = new AbortController();
    pairings.set(userId, abort);
    const budget = config.connectBudgetSats
      ? ` and, if you allow sending, a limit of ${config.connectBudgetSats.toLocaleString('en-US')} sats per day`
      : '';
    await send(
      userId,
      [
        '<b>Connect your Blitz Wallet</b>',
        `Tap the button on the phone where Blitz is installed and approve the request. The bot gets access to your Wallet Connect account (a separate balance)${budget}. You can change or remove it any time in Blitz → Settings → Wallet Connect.`,
        '',
        'Nothing secret is shared: there is no connection string to copy.',
        '',
        `This link works for ${LIMITS.pairingTimeoutMs / MIN} minutes. Blitz on another device? Scan or paste this in Blitz:`,
        `<code>${uri}</code>`,
        '',
        'Older Blitz version? Use /connect_manual.',
      ].join('\n'),
      {
        reply_markup: {
          inline_keyboard: [[{ text: 'Connect in Blitz', url: link }]],
        },
      },
    );

    // Not tracked for shutdown: a pending link is not work in progress; the
    // completion itself runs on the user's chain, which drain() does wait for.
    nwc
      .waitForPairing(
        { clientPubkey, state, relays },
        { timeoutMs: LIMITS.pairingTimeoutMs, signal: abort.signal },
      )
      .then(info =>
        runForUser(userId, async () => {
          if (pairings.get(userId) !== abort) return; // superseded meanwhile
          if (store.inFlightPaymentCount(userId) > 0) {
            return send(
              userId,
              'Blitz approved the connection, but a payment is still being confirmed, so I didn’t switch. Delete the new connection in Blitz → Settings → Wallet Connect and try /connect again later.',
            );
          }
          await saveConnection(
            userId,
            {
              walletPubkey: info.walletPubkey,
              relays: info.relays,
              secret,
              encryption: info.encryption,
            },
            info.methods,
          );
        }),
      )
      .catch(err => {
        if (abort.signal.aborted) return; // replaced by a newer link
        if (err instanceof ConnectionStringError) {
          return send(
            userId,
            'Your wallet asked to use a relay this bot doesn’t support, so I didn’t connect. Delete the new connection in Blitz → Settings → Wallet Connect.',
          );
        }
        if (err instanceof NwcTimeoutError) {
          return send(
            userId,
            'The connection link expired. Send /connect for a new one.',
          );
        }
        log.error('pairing failed', { err, user: log.user(userId) });
      })
      .finally(() => pairings.get(userId) === abort && pairings.delete(userId));
  }

  // --------------------------------------------------------------- PIN pad

  const keypadMarkup = nonce => ({
    inline_keyboard: [
      ['1', '2', '3'],
      ['4', '5', '6'],
      ['7', '8', '9'],
      ['b', '0', 'x'],
    ].map(row =>
      row.map(k => ({
        text: k === 'b' ? '⌫' : k === 'x' ? '✖ Cancel' : k,
        callback_data: `k:${nonce}:${k}`,
      })),
    ),
  });
  const dots = n => '●'.repeat(n) + '○'.repeat(LIMITS.pinLength - n);

  async function startPinSession(userId, session, prompt, messageId) {
    const s = {
      ...session,
      nonce: randomBytes(9).toString('base64url'),
      digits: '',
      prompt,
      expiresAt: now() + LIMITS.pinSessionMs,
    };
    pinSessions.set(userId, s);
    const text = `${prompt}\n\n<code>${dots(0)}</code>`;
    if (messageId) {
      s.messageId = messageId;
      return edit(userId, messageId, text, {
        reply_markup: keypadMarkup(s.nonce),
      });
    }
    const sent = await send(userId, text, {
      reply_markup: keypadMarkup(s.nonce),
    });
    s.messageId = sent?.message_id;
  }

  async function keypad(userId, messageId, nonce, key) {
    const s = pinSessions.get(userId);
    if (
      !s ||
      s.nonce !== nonce ||
      s.expiresAt < now() ||
      s.messageId !== messageId
    ) {
      return edit(userId, messageId, 'This keypad has expired.');
    }
    if (key === 'x') {
      pinSessions.delete(userId);
      if (s.purpose === 'pay') store.cancelPayment(s.paymentId, userId, now());
      return edit(
        userId,
        messageId,
        s.purpose === 'pay'
          ? 'Payment cancelled. Nothing was sent.'
          : 'PIN setup cancelled. You’ll be asked to set a PIN before your first payment.',
      );
    }
    if (key === 'b') s.digits = s.digits.slice(0, -1);
    else if (key && s.digits.length < LIMITS.pinLength) s.digits += key;
    if (s.digits.length < LIMITS.pinLength) {
      return edit(
        userId,
        messageId,
        `${s.prompt}\n\n<code>${dots(s.digits.length)}</code>`,
        { reply_markup: keypadMarkup(s.nonce) },
      );
    }

    const pin = s.digits;
    s.digits = '';
    if (s.purpose === 'set') {
      if (isWeakPin(pin)) {
        s.prompt =
          'That PIN is too easy to guess. Choose a different 6-digit PIN.';
        return edit(
          userId,
          messageId,
          `${s.prompt}\n\n<code>${dots(0)}</code>`,
          { reply_markup: keypadMarkup(s.nonce) },
        );
      }
      Object.assign(s, {
        purpose: 'repeat',
        first: pin,
        prompt: 'Enter the same PIN again to confirm.',
      });
      return edit(userId, messageId, `${s.prompt}\n\n<code>${dots(0)}</code>`, {
        reply_markup: keypadMarkup(s.nonce),
      });
    }
    if (s.purpose === 'repeat') {
      if (pin !== s.first) {
        Object.assign(s, {
          purpose: 'set',
          first: null,
          prompt: 'The PINs didn’t match. Choose a 6-digit PIN.',
        });
        return edit(
          userId,
          messageId,
          `${s.prompt}\n\n<code>${dots(0)}</code>`,
          { reply_markup: keypadMarkup(s.nonce) },
        );
      }
      pinSessions.delete(userId);
      if (!store.getWallet(userId))
        return edit(userId, messageId, 'Your wallet is no longer connected.');
      store.setPin(userId, await hashPin(pin));
      return edit(
        userId,
        messageId,
        '🔐 Payment PIN set. Paste a Lightning invoice any time to pay it.',
      );
    }
    // purpose === 'pay'
    return finishPinForPayment(userId, messageId, s, pin);
  }

  // ---------------------------------------------------------------- sending

  async function startSend(userId, text) {
    const wallet = store.getWallet(userId);
    if (!wallet)
      return send(userId, 'Connect your wallet first with /connect.');
    const can = methodsOf(wallet);
    if (!can.has('pay_invoice') || !can.has('lookup_invoice')) {
      return send(
        userId,
        'Sending isn’t enabled for this connection. In Blitz, create a connection with Send payments and Lookup Invoice enabled, then paste it here.',
      );
    }
    if (!wallet.pin_hash) {
      return startPinSession(
        userId,
        { purpose: 'set' },
        'Before your first payment, choose a 6-digit <b>payment PIN</b>. Then send the invoice again.',
      );
    }

    const raw = findInvoice(text);
    let inv;
    try {
      if (!raw) throw new InvoiceError('invalid');
      inv = decodeInvoice(raw, now());
    } catch (err) {
      if (!(err instanceof InvoiceError)) throw err;
      return send(
        userId,
        {
          network: 'That invoice isn’t for Bitcoin mainnet.',
          no_amount:
            'That invoice has no amount. Ask the recipient for an invoice with an amount.',
          expired:
            'That invoice has expired (or is about to). Ask the recipient for a new one.',
        }[err.reason] ?? 'That doesn’t look like a valid Lightning invoice.',
      );
    }
    if (inv.amountMsat > config.maxPaymentSats * 1000) {
      return send(
        userId,
        `That’s more than this bot allows per payment (${config.maxPaymentSats.toLocaleString('en-US')} sats). Use the Blitz app for larger payments.`,
      );
    }
    const blocking = store.blockingPaymentForHash(userId, inv.paymentHash);
    if (blocking) {
      return send(
        userId,
        blocking.status === 'paid'
          ? 'You already paid this invoice.'
          : 'A payment for this invoice is already in progress. Don’t pay it again — check /status.',
      );
    }

    const t = now();
    const id = randomId();
    store.cancelAwaiting(userId, t);
    if (pinSessions.get(userId)?.purpose === 'pay') pinSessions.delete(userId);
    store.createPayment({
      id,
      userId,
      paymentHash: inv.paymentHash,
      invoice: inv.invoice,
      amountMsat: inv.amountMsat,
      confirmExpiresAt: Math.min(
        t + LIMITS.confirmTtlMs,
        inv.expiresAt - 30_000,
      ),
      now: t,
    });
    // Recipient-controlled text: strip control and bidi-override characters
    // that could visually rearrange the confirmation screen.
    const memo = inv.description
      ? escapeHtml(
          inv.description
            .replace(
              /[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
              '',
            )
            .slice(0, 200),
        )
      : '<i>none</i>';
    return send(
      userId,
      [
        '<b>You’re about to pay</b>',
        '',
        `Amount: <b>${sats(inv.amountMsat)} sats</b> (+ network fee)`,
        `Memo (written by the recipient): ${memo}`,
        `Invoice expires in: ${minutesUntil(inv.expiresAt, t)} min`,
        `Payment hash: <code>${inv.paymentHash.slice(0, 16)}…</code>`,
        '',
        'Only confirm if you expected this payment.',
      ].join('\n'),
      {
        reply_markup: {
          inline_keyboard: [
            [
              { text: '✅ Confirm payment', callback_data: `pc:${id}` },
              { text: 'Cancel', callback_data: `px:${id}` },
            ],
          ],
        },
      },
    );
  }

  async function confirmPayment(userId, messageId, paymentId) {
    const p = store.getPayment(paymentId, userId);
    if (
      !p ||
      p.status !== 'awaiting_confirmation' ||
      p.confirm_expires_at <= now()
    ) {
      return edit(
        userId,
        messageId,
        'This payment request has expired or was already handled. Paste the invoice again if you still want to pay it.',
      );
    }
    const wallet = store.getWallet(userId);
    if (!wallet?.pin_hash)
      return edit(userId, messageId, 'Your wallet is no longer connected.');
    if (wallet.pin_locked_until > now()) {
      return edit(
        userId,
        messageId,
        `Payments are locked after too many wrong PINs. Try again in ${minutesUntil(wallet.pin_locked_until, now())} min.`,
      );
    }
    return startPinSession(
      userId,
      { purpose: 'pay', paymentId },
      `Enter your PIN to pay <b>${sats(p.amount_msat)} sats</b>.`,
      messageId,
    );
  }

  async function finishPinForPayment(userId, messageId, s, pin) {
    const wallet = store.getWallet(userId);
    if (!wallet?.pin_hash) {
      pinSessions.delete(userId);
      return edit(userId, messageId, 'Your wallet is no longer connected.');
    }
    if (wallet.pin_locked_until > now()) {
      pinSessions.delete(userId);
      store.cancelPayment(s.paymentId, userId, now());
      return edit(
        userId,
        messageId,
        'Payments are locked after too many wrong PINs. Nothing was sent.',
      );
    }
    if (!(await verifyPin(pin, wallet.pin_hash))) {
      const r = store.recordPinFailure(
        userId,
        now(),
        LIMITS.pinMaxFailures,
        LIMITS.pinLockMs,
      );
      log.warn('wrong payment pin', {
        user: log.user(userId),
        locked: r.locked,
      });
      if (r.locked) {
        pinSessions.delete(userId);
        store.cancelPayment(s.paymentId, userId, now());
        return edit(
          userId,
          messageId,
          'Too many wrong PINs. Payments are locked for 1 hour. Nothing was sent.\nForgot your PIN? Use /disconnect and connect again.',
        );
      }
      s.prompt = `Wrong PIN. ${r.remaining} attempt${r.remaining === 1 ? '' : 's'} left before payments are locked.`;
      return edit(userId, messageId, `${s.prompt}\n\n<code>${dots(0)}</code>`, {
        reply_markup: keypadMarkup(s.nonce),
      });
    }
    pinSessions.delete(userId);
    store.resetPinFailures(userId);

    let conn;
    try {
      conn = connFor(wallet);
    } catch (err) {
      log.error('cannot decrypt wallet secret', {
        user: log.user(userId),
        err,
      });
      store.cancelPayment(s.paymentId, userId, now());
      return edit(
        userId,
        messageId,
        'Your connection can’t be used anymore. Nothing was sent. Please /connect again.',
      );
    }
    const payment = store.getPayment(s.paymentId, userId);
    if (
      !payment?.invoice ||
      !store.claimForSubmit(s.paymentId, userId, now())
    ) {
      const reason =
        store.inFlightPaymentCount(userId) > 0
          ? 'Another payment is still in progress. Wait for it to finish (see /status).'
          : 'This payment request has expired or was already handled.';
      store.cancelPayment(s.paymentId, userId, now());
      return edit(userId, messageId, `${reason} Nothing was sent.`);
    }
    await edit(
      userId,
      messageId,
      `⚡ Sending <b>${sats(payment.amount_msat)} sats</b>… Don’t pay this invoice again while this is in progress.`,
    );
    track(submitPayment(payment, conn));
  }

  // Sends pay_invoice exactly once. The request id and expiration are stored
  // before publishing; any outcome other than a definitive answer is
  // 'unknown' and goes to the reconciler. There is no retry path.
  async function submitPayment(payment, conn) {
    submitting.add(payment.id);
    try {
      const request = nwc.buildRequest(
        conn,
        'pay_invoice',
        { invoice: payment.invoice },
        { expiresInSec: LIMITS.payExpiresInSec },
      );
      store.setPaymentRequest(
        payment.id,
        request.event.id,
        request.expiresAt,
        now(),
      );
      let response;
      try {
        response = await nwc.send(conn, request, {
          timeoutMs: LIMITS.payTimeoutMs,
        });
      } catch (err) {
        if (!(err instanceof NwcTimeoutError))
          log.error('pay_invoice send error', { err });
      }
      const outcome = classifyPayResponse(response, payment.payment_hash);
      log.info('payment outcome', {
        user: log.user(payment.user_id),
        status: outcome.status,
        reason: outcome.reason ?? response?.error?.code,
      });
      applyPaymentOutcome(payment, outcome, true);
    } catch (err) {
      // e.g. DB failure after claiming. The row stays 'submitting' and
      // recoverSubmitting() turns it into 'unknown' on the next start.
      log.error('payment submit failed', { err });
      await send(
        payment.user_id,
        '⚠️ I couldn’t confirm this payment yet. <b>Don’t pay the invoice again.</b> Check Blitz; I’ll message you when I know more.',
      );
    } finally {
      submitting.delete(payment.id);
    }
  }

  function applyPaymentOutcome(payment, outcome, firstAttempt) {
    const t = now();
    const checks = firstAttempt ? 0 : payment.checks + 1;
    if (outcome.status === 'unknown') {
      const givingUp = t - payment.created_at > LIMITS.unknownGiveUpMs;
      store.updatePayment(payment.id, {
        status: 'unknown',
        checks,
        nextCheckAt: givingUp
          ? null
          : t + Math.min(6 * 60 * MIN, MIN * 2 ** checks),
        now: t,
      });
      if (firstAttempt) {
        return track(
          send(
            payment.user_id,
            `⏳ I couldn’t confirm the payment of <b>${sats(payment.amount_msat)} sats</b> yet. It may still go through. <b>Don’t pay this invoice again.</b> I’ll message you when it’s resolved; you can also check /status or the Blitz app.`,
          ),
        );
      }
      if (givingUp && payment.next_check_at !== null) {
        return track(
          send(
            payment.user_id,
            `⚠️ The payment of <b>${sats(payment.amount_msat)} sats</b> is still unconfirmed after 3 days. Please check the Blitz app for its final status.`,
          ),
        );
      }
      return;
    }
    if (
      !store.updatePayment(payment.id, {
        status: outcome.status,
        feeMsat: outcome.feeMsat ?? null,
        checks,
        now: t,
      })
    )
      return;
    if (outcome.status === 'paid') {
      // Paid a request posted through this bot: tell the requester right away
      // instead of waiting for their next scheduled check.
      const requested = store.openInvoiceByHash(payment.payment_hash);
      if (requested) track(reconcileInvoice(requested).catch(() => {}));
      const fee =
        outcome.feeMsat != null ? ` (fee ${sats(outcome.feeMsat)} sats)` : '';
      return track(
        send(
          payment.user_id,
          `✅ Paid <b>${sats(payment.amount_msat)} sats</b>${fee}.`,
        ),
      );
    }
    const why =
      {
        QUOTA_EXCEEDED:
          'This would exceed the budget you set for this connection in Blitz.',
        INSUFFICIENT_BALANCE:
          'Your Wallet Connect account doesn’t have enough funds.',
        RESTRICTED: 'This connection isn’t allowed to send payments.',
        UNAUTHORIZED: 'The connection was removed in Blitz.',
        RATE_LIMITED: 'The wallet is busy; try again in a moment.',
        NOT_SENT: 'The wallet never received the request in time.',
      }[outcome.reason] ?? 'The payment didn’t go through.';
    return track(
      send(
        payment.user_id,
        `❌ Payment of <b>${sats(payment.amount_msat)} sats</b> failed. No money left your wallet. ${why}`,
      ),
    );
  }

  async function reconcilePayment(payment) {
    if (submitting.has(payment.id)) return;
    const wallet = store.getWallet(payment.user_id);
    if (!wallet) return;
    const res = await walletCall(connFor(wallet), 'lookup_invoice', {
      payment_hash: payment.payment_hash,
    });
    applyPaymentOutcome(
      payment,
      classifyPaymentLookup(res, payment, now()),
      false,
    );
  }

  // -------------------------------------------------------------- receiving

  function nextInvoiceCheck(inv, t) {
    const at = [
      ...LIMITS.invoiceCheckMinutes.map(m => inv.created_at + m * MIN),
      inv.expires_at + MIN,
    ].filter(x => x <= inv.expires_at + MIN);
    return at.find(x => x > t) ?? null;
  }

  // "21,000 coffee" -> { amount: 21000, memo: 'coffee' }, or null.
  function parseAmountMemo(text) {
    const m = /^([\d,_]+)\s*([\s\S]*)$/.exec(String(text).trim());
    const amount = m ? Number(m[1].replace(/[,_]/g, '')) : NaN;
    if (
      !Number.isSafeInteger(amount) ||
      amount < 1 ||
      amount > LIMITS.maxReceiveSats
    ) {
      return null;
    }
    const memo = m[2]
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u001f\u007f]/g, ' ')
      .trim()
      .slice(0, 100);
    return { amount, memo };
  }

  // Shared by /receive and inline mode. Returns { inv, id, tracked } or
  // { error } with a user-facing message.
  async function createInvoice(
    userId,
    { amount, memo },
    { inlineMessageId } = {},
  ) {
    const wallet = store.getWallet(userId);
    if (!wallet) return { error: 'Connect your wallet first with /connect.' };
    if (!methodsOf(wallet).has('make_invoice')) {
      return {
        error:
          'Receiving isn’t enabled for this connection (enable Receive payments in Blitz and /connect again).',
      };
    }
    if (store.openInvoiceCount(userId) >= LIMITS.maxOpenInvoices) {
      return {
        error: `You already have ${LIMITS.maxOpenInvoices} open invoices. Wait for them to be paid or expire (see /status).`,
      };
    }
    if (!allow(userId, 'wallet')) {
      return { error: 'Slow down a little and try again in a minute.' };
    }

    const res = await walletCall(connFor(wallet), 'make_invoice', {
      amount: amount * 1000,
      ...(memo ? { description: memo } : {}),
      expiry: LIMITS.invoiceExpirySec,
    });
    if (!res.result) return { error: walletTrouble(res) };
    let inv;
    try {
      inv = decodeInvoice(
        String(res.result.invoice ?? '').toLowerCase(),
        now(),
        0,
      );
    } catch {
      log.warn('wallet returned an unusable invoice', {
        user: log.user(userId),
      });
      return {
        error:
          'Your wallet returned an invoice I couldn’t verify, so I won’t show it. Please try again.',
      };
    }
    if (inv.amountMsat !== amount * 1000) {
      log.warn('wallet invoice amount mismatch', { user: log.user(userId) });
      return {
        error:
          'Your wallet returned an invoice for a different amount, so I won’t show it. Please try again.',
      };
    }

    const t = now();
    const id = randomId();
    const tracked = methodsOf(wallet).has('lookup_invoice');
    store.createInvoice({
      id,
      userId,
      paymentHash: inv.paymentHash,
      amountMsat: inv.amountMsat,
      expiresAt: inv.expiresAt,
      nextCheckAt: tracked
        ? nextInvoiceCheck({ created_at: t, expires_at: inv.expiresAt }, t)
        : null,
      ...(inlineMessageId ? { invoice: inv.invoice, inlineMessageId } : {}),
      now: t,
    });
    return { inv, id, tracked };
  }

  async function receive(userId, args) {
    const parsed = parseAmountMemo(args);
    if (!parsed) {
      return send(
        userId,
        'Usage: <code>/receive 21000 optional memo</code> (amount in sats).',
      );
    }
    const { inv, id, tracked, error } = await createInvoice(userId, parsed);
    if (error) return send(userId, error);
    await send(
      userId,
      `Invoice for <b>${sats(inv.amountMsat)} sats</b>${parsed.memo ? ` (${escapeHtml(parsed.memo)})` : ''}, expires in ${minutesUntil(inv.expiresAt, now())} min:`,
    );
    return send(
      userId,
      `<code>${inv.invoice}</code>`,
      tracked
        ? {
            reply_markup: {
              inline_keyboard: [
                [{ text: '🔄 Check if paid', callback_data: `ic:${id}` }],
              ],
            },
          }
        : {},
    );
  }

  // ----------------------------------------------------------- inline mode
  //
  // "@bot 5000 pizza" in any chat. Typing only previews (no wallet call, since
  // Telegram sends a query per keystroke and each wallet call wakes the
  // phone). The invoice is created once the user picks the result
  // (chosen_inline_result, needs /setinlinefeedback). Only invoices: nothing
  // that reads or spends the wallet is reachable from other chats.

  async function onInlineQuery(q) {
    const userId = q.from.id;
    const answer = (results, button) =>
      safe(
        tg.call('answerInlineQuery', {
          inline_query_id: q.id,
          results,
          // Results are per user: never let Telegram cache or share them.
          cache_time: 0,
          is_personal: true,
          ...(button ? { button } : {}),
        }),
      );
    if (config.allowedUsers && !config.allowedUsers.has(userId))
      return answer([]);
    const wallet = store.getWallet(userId);
    if (!wallet || !methodsOf(wallet).has('make_invoice')) {
      return answer([], {
        text: 'Connect your Blitz Wallet first',
        start_parameter: 'connect',
      });
    }
    const parsed = parseAmountMemo(q.query);
    if (!parsed) {
      return answer([], {
        text: 'Type an amount in sats, e.g. 5000 pizza',
        start_parameter: 'help',
      });
    }
    const memo = parsed.memo ? ` — ${escapeHtml(parsed.memo)}` : '';
    return answer([
      {
        type: 'article',
        id: 'invoice',
        thumbnail_url: INLINE_THUMBNAIL_URL,
        thumbnail_width: 512,
        thumbnail_height: 512,
        title: `Request ${sats(parsed.amount * 1000)} sats`,
        description:
          parsed.memo || 'Creates a Lightning invoice from your Blitz Wallet',
        input_message_content: {
          message_text: `⚡ <b>${sats(parsed.amount * 1000)} sats</b> requested${memo}\nCreating invoice…`,
          parse_mode: 'HTML',
        },
        // A keyboard is what makes Telegram hand us an inline_message_id to edit.
        reply_markup: {
          inline_keyboard: [
            [{ text: '⏳ Creating invoice…', callback_data: 'nop:0' }],
          ],
        },
      },
    ]);
  }

  async function onChosenInlineResult(r) {
    const userId = r.from.id;
    if (!r.inline_message_id) return;
    const editInline = (text, replyMarkup) =>
      safe(
        tg.call('editMessageText', {
          inline_message_id: r.inline_message_id,
          text,
          parse_mode: 'HTML',
          disable_web_page_preview: true,
          ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
        }),
      );
    if (config.allowedUsers && !config.allowedUsers.has(userId)) {
      return editInline('This bot is private.');
    }
    // Re-parse: `query` comes from the client, nothing from the preview is trusted.
    const parsed = parseAmountMemo(r.query);
    if (!parsed)
      return editInline('Couldn’t create an invoice for that amount.');
    const { inv, id, error } = await createInvoice(userId, parsed, {
      inlineMessageId: r.inline_message_id,
    });
    if (error) {
      // The explanation goes privately to the requester, not into the chat.
      await send(userId, error);
      return editInline('Couldn’t create the invoice.');
    }
    const memo = parsed.memo ? ` — ${escapeHtml(parsed.memo)}` : '';
    // The invoice itself stays out of the message text: the buttons open it
    // in a wallet, copy it, or pay it through the bot.
    return editInline(
      `⚡ <b>${sats(inv.amountMsat)} sats</b> requested${memo}\nExpires in ${minutesUntil(inv.expiresAt, now())} min.`,
      invoiceButtons(inv.invoice, id),
    );
  }

  function invoiceButtons(invoice, id) {
    const copy =
      invoice.length <= MAX_COPY_TEXT
        ? { text: '📋 Copy invoice', copy_text: { text: invoice } }
        : { text: '📋 Copy invoice', url: `${PAY_PAGE_URL}#${invoice}` };
    return {
      inline_keyboard: [
        [
          { text: '⚡ Open wallet', url: `${PAY_PAGE_URL}#open:${invoice}` },
          copy,
        ],
        [
          {
            text: config.botUsername
              ? `Pay with @${config.botUsername}`
              : 'Pay in Telegram',
            callback_data: `ip:${id}`,
          },
        ],
      ],
    };
  }

  // "Pay" on a posted invoice. Paying needs Confirm + PIN, which must never
  // happen in a shared chat, so the button only opens the private chat
  // (t.me/<bot>?start=pay_<id>) where the normal send flow takes over.
  async function payPostedInvoice(cq, id, answer) {
    const userId = cq.from.id;
    if (config.allowedUsers && !config.allowedUsers.has(userId)) {
      return answer('This bot is private.');
    }
    if (!allow(userId, 'update')) return answer('Slow down a little.');
    const inv = store.getPostedInvoice(id);
    if (!inv) return answer('This invoice was already paid or has expired.');
    if (inv.user_id === userId) return answer('This is your own invoice.');
    if (!config.botUsername) return answer('Open the bot to pay this invoice.');
    return safe(
      tg.call('answerCallbackQuery', {
        callback_query_id: cq.id,
        url: `https://t.me/${config.botUsername}?start=pay_${id}`,
      }),
    );
  }

  async function payPosted(userId, id) {
    const inv = store.getPostedInvoice(id);
    if (!inv)
      return send(userId, 'That invoice was already paid or has expired.');
    if (inv.user_id === userId) return send(userId, 'That’s your own invoice.');
    return startSend(userId, inv.invoice);
  }

  // Returns the new status, or null if unchanged/unknown.
  async function reconcileInvoice(inv, { manual = false } = {}) {
    const wallet = store.getWallet(inv.user_id);
    if (!wallet) return null;
    const t = now();
    const res = await walletCall(connFor(wallet), 'lookup_invoice', {
      payment_hash: inv.payment_hash,
    });
    const r = res.result;
    let status = null;
    if (
      r &&
      (r.state === 'settled' ||
        isValidPreimage(r.preimage, inv.payment_hash)) &&
      (!r.type || r.type === 'incoming')
    ) {
      status = 'paid';
    } else if ((r && r.state === 'expired') || t > inv.expires_at) {
      status = 'expired';
    }
    const checks = inv.checks + 1;
    if (!status) {
      if (!manual)
        store.updateInvoice(inv.id, {
          status: 'open',
          checks,
          nextCheckAt: nextInvoiceCheck(inv, t),
          now: t,
        });
      return null;
    }
    if (
      !store.updateInvoice(inv.id, {
        status,
        checks,
        nextCheckAt: null,
        now: t,
      })
    )
      return null;
    if (status === 'paid')
      track(
        send(inv.user_id, `💰 Received <b>${sats(inv.amount_msat)} sats</b>.`),
      );
    if (inv.inline_message_id) {
      track(
        safe(
          tg.call('editMessageText', {
            inline_message_id: inv.inline_message_id,
            parse_mode: 'HTML',
            text:
              status === 'paid'
                ? `✅ <b>${sats(inv.amount_msat)} sats</b> paid.`
                : `⌛ Invoice for <b>${sats(inv.amount_msat)} sats</b> expired unpaid.`,
          }),
        ),
      );
    }
    return status;
  }

  async function checkInvoice(userId, id) {
    const inv = store.getInvoice(id, userId);
    if (!inv) return send(userId, 'I’m no longer tracking that invoice.');
    if (inv.status !== 'open')
      return send(
        userId,
        inv.status === 'paid'
          ? 'That invoice is paid ✅'
          : 'That invoice expired unpaid.',
      );
    if (!allow(userId, 'wallet'))
      return send(userId, 'Slow down a little and try again in a minute.');
    const status = await reconcileInvoice(inv, { manual: true });
    if (!status) return send(userId, 'Not paid yet.');
    if (status === 'expired')
      return send(userId, 'That invoice expired unpaid.');
  }

  // ------------------------------------------------------------- read-only

  async function balance(userId) {
    const wallet = store.getWallet(userId);
    if (!wallet)
      return send(userId, 'Connect your wallet first with /connect.');
    if (!methodsOf(wallet).has('get_balance'))
      return send(userId, 'Balance isn’t enabled for this connection.');
    if (!allow(userId, 'wallet'))
      return send(userId, 'Slow down a little and try again in a minute.');
    const res = await walletCall(connFor(wallet), 'get_balance', {});
    const msat = Number(res.result?.balance);
    if (!res.result || !Number.isFinite(msat) || msat < 0)
      return send(userId, walletTrouble(res));
    return send(userId, `Wallet Connect balance: <b>${sats(msat)} sats</b>`);
  }

  async function transactions(userId, page, messageId) {
    const wallet = store.getWallet(userId);
    if (!wallet)
      return send(userId, 'Connect your wallet first with /connect.');
    if (!methodsOf(wallet).has('list_transactions'))
      return send(userId, 'Transactions aren’t enabled for this connection.');
    page = Math.min(Math.max(0, Math.floor(page)), LIMITS.txMaxPages - 1);
    if (!allow(userId, 'wallet'))
      return send(userId, 'Slow down a little and try again in a minute.');
    const res = await walletCall(connFor(wallet), 'list_transactions', {
      limit: LIMITS.txPageSize,
      offset: page * LIMITS.txPageSize,
    });
    const list = res.result?.transactions;
    if (!Array.isArray(list)) return send(userId, walletTrouble(res));

    // Memos are deliberately not shown: they can hold personal details and
    // Telegram keeps chat history. They remain visible in the Blitz app.
    const lines = list.slice(0, LIMITS.txPageSize).flatMap(tx => {
      const amount = Number(tx.amount);
      if (!Number.isFinite(amount) || amount < 0) return [];
      const when = Number.isFinite(Number(tx.created_at))
        ? fmtDate(Number(tx.created_at))
        : 'unknown date';
      const dir = tx.type === 'incoming' ? '⬇️ Received' : '⬆️ Sent';
      const fee =
        Number(tx.fees_paid) > 0 && tx.type !== 'incoming'
          ? ` · fee ${sats(Number(tx.fees_paid))}`
          : '';
      const state = ['pending', 'failed', 'expired'].includes(tx.state)
        ? ` · ${tx.state}`
        : '';
      return [`${when}  ${dir} <b>${sats(amount)}</b> sats${fee}${state}`];
    });
    const text = lines.length
      ? `<b>Wallet Connect activity</b> (page ${page + 1})\n\n${lines.join('\n')}`
      : page === 0
        ? 'No transactions yet.'
        : 'No more transactions.';
    const nav = [];
    if (page > 0)
      nav.push({ text: '« Newer', callback_data: `tx:${page - 1}` });
    if (list.length >= LIMITS.txPageSize && page < LIMITS.txMaxPages - 1)
      nav.push({ text: 'Older »', callback_data: `tx:${page + 1}` });
    const extra = nav.length
      ? { reply_markup: { inline_keyboard: [nav] } }
      : {};
    return messageId
      ? edit(userId, messageId, text, extra)
      : send(userId, text, extra);
  }

  const PAY_LABEL = {
    submitting: '⏳ sending',
    unknown: '⏳ unconfirmed',
    paid: '✅ paid',
    failed: '❌ failed',
    cancelled: 'cancelled',
  };
  const INV_LABEL = {
    open: '⏳ waiting',
    paid: '✅ paid',
    expired: 'expired',
    untracked: 'not tracked',
  };

  async function status(userId) {
    if (!store.getWallet(userId))
      return send(userId, 'Connect your wallet first with /connect.');
    const payments = store.recentPayments(userId);
    const invoices = store.recentInvoices(userId);
    if (!payments.length && !invoices.length)
      return send(
        userId,
        'Nothing to report: no recent payments or invoices from this bot.',
      );
    const lines = [];
    if (payments.length) {
      lines.push('<b>Payments</b>');
      for (const p of payments)
        lines.push(
          `${fmtDate(p.created_at / 1000)}  ${sats(p.amount_msat)} sats  ${PAY_LABEL[p.status] ?? p.status}`,
        );
    }
    if (invoices.length) {
      lines.push('', '<b>Invoices</b>');
      for (const i of invoices)
        lines.push(
          `${fmtDate(i.created_at / 1000)}  ${sats(i.amount_msat)} sats  ${INV_LABEL[i.status] ?? i.status}`,
        );
    }
    const pending =
      payments.some(p => p.status === 'unknown') ||
      invoices.some(i => i.status === 'open');
    return send(
      userId,
      lines.join('\n'),
      pending
        ? {
            reply_markup: {
              inline_keyboard: [
                [{ text: '🔄 Refresh', callback_data: 'sr:all' }],
              ],
            },
          }
        : {},
    );
  }

  async function refreshStatus(userId) {
    if (!allow(userId, 'wallet'))
      return send(userId, 'Slow down a little and try again in a minute.');
    for (const p of store.recentPayments(userId))
      if (p.status === 'unknown') await reconcilePayment(p);
    for (const i of store.recentInvoices(userId))
      if (i.status === 'open') await reconcileInvoice(i, { manual: true });
    return status(userId);
  }

  // ------------------------------------------------------------- disconnect

  async function askDisconnect(userId) {
    if (!store.getWallet(userId))
      return send(userId, 'No wallet is connected.');
    const warn =
      store.inFlightPaymentCount(userId) > 0
        ? '\n\n⚠️ A payment is still unconfirmed; after disconnecting I can’t tell you how it ends — check Blitz.'
        : '';
    return send(
      userId,
      `Disconnect your wallet? I’ll delete the connection and everything I stored about your payments and invoices.${warn}`,
      {
        reply_markup: {
          inline_keyboard: [
            [
              { text: 'Disconnect', callback_data: 'dc:yes' },
              { text: 'Keep', callback_data: 'dc:no' },
            ],
          ],
        },
      },
    );
  }

  async function disconnect(userId, messageId) {
    store.deleteUser(userId);
    pinSessions.delete(userId);
    pairings.get(userId)?.abort();
    log.info('wallet disconnected', { user: log.user(userId) });
    return edit(
      userId,
      messageId,
      'Disconnected. I deleted your connection and all related data.\n\n<b>To fully revoke access</b>, open Blitz → Settings → Wallet Connect and delete the Telegram connection. Until you do, that connection string still works.',
    );
  }

  // ------------------------------------------------------------ maintenance

  // Runs every ~30 s: expires confirmations, reconciles unknown payments and
  // open invoices with backoff, purges old rows, trims in-memory state.
  async function runMaintenance() {
    if (maintenanceRunning) return;
    maintenanceRunning = true;
    try {
      const t = now();
      store.expireConfirmations(t);
      await Promise.allSettled(store.duePayments(t, 10).map(reconcilePayment));
      await Promise.allSettled(
        store.dueInvoices(t, 10).map(inv => reconcileInvoice(inv)),
      );
      store.purge(t, LIMITS.retentionMs);
      for (const [userId, s] of pinSessions)
        if (s.expiresAt < t) pinSessions.delete(userId);
      for (const [key, b] of buckets)
        if (t - b.at > 10 * MIN) buckets.delete(key);
    } catch (err) {
      log.error('maintenance failed', { err });
    } finally {
      maintenanceRunning = false;
    }
  }

  async function drain(timeoutMs = 10_000) {
    const all = Promise.allSettled([...chains.values(), ...background]);
    await Promise.race([
      all,
      new Promise(r => setTimeout(r, timeoutMs).unref()),
    ]);
  }

  return {
    handleUpdate,
    runMaintenance,
    drain,
    _internals: { pinSessions, submitting },
  };
}
