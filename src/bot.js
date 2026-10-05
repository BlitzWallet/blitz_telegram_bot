import { randomBytes } from 'node:crypto';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { hashPin, randomId, verifyPin } from './crypto.js';
import {
  LANGUAGE_NAMES,
  SUPPORTED_LOCALES,
  normalizeLocale,
  t,
  tFor,
} from './i18n.js';
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
// These are all pre-send checks (quota, balance, permission, support). A
// generic PAYMENT_FAILED, INTERNAL, OTHER, timeouts, or a result without a
// valid preimage is "unknown" and is reconciled, never retried: the wallet
// may have submitted the payment before the error reached us (H1).
const DEFINITIVE_PAY_ERRORS = new Set([
  'QUOTA_EXCEEDED',
  'INSUFFICIENT_BALANCE',
  'RESTRICTED',
  'UNAUTHORIZED',
  'RATE_LIMITED',
  'NOT_IMPLEMENTED',
  'UNSUPPORTED_ENCRYPTION',
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
// A wallet-reported state of 'failed' is NOT trusted as final: Blitz's JS
// handler records 'failed' even when the payment was already submitted
// (network error after submission, PREIMAGE_PROVIDING_FAILED /
// TRANSFER_FAILED arriving after LIGHTNING_PAYMENT_SUCCEEDED). Treat it as
// 'unknown' so the reconciler keeps checking instead of freeing the invoice
// for a double payment (H1).
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
const sats = (msat, locale = 'en') => {
  try {
    return Math.floor(msat / 1000).toLocaleString(locale);
  } catch {
    return Math.floor(msat / 1000).toLocaleString('en');
  }
};
// Short, non-secret wallet identifier shown wherever money is discussed so a
// silently-switched connection is visible (H3). The pubkey itself is not
// secret (it is the author of a public kind-13194 event).
const shortWalletId = pubkey =>
  typeof pubkey === 'string' && /^[0-9a-f]{64}$/i.test(pubkey)
    ? `${pubkey.slice(0, 8)}…`
    : null;
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

// Per-user text: HELP/PASTE_HOWTO depend on the user's language.
const helpFor = lng => tFor(lng)('help');
const pasteHowtoFor = lng => tFor(lng)('paste_howto');

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

  // --- language ------------------------------------------------------------
  // Stored per user via /connect or /language; falls back to Telegram's
  // language_code on first contact, then 'en'. All user-facing text goes
  // through tu(userId) so each user sees their own language.
  const localeOf = (userId, tgLang) => {
    try {
      const saved = store.getLocale?.(userId);
      if (saved) return normalizeLocale(saved);
    } catch {}
    if (tgLang) return normalizeLocale(tgLang);
    return 'en';
  };
  const tu = (userId, tgLang) => tFor(localeOf(userId, tgLang));
  const satsU = userId => (msat, tgLang) =>
    sats(msat, localeOf(userId, tgLang));

  const languageRows = (current, action = 'lg') => {
    const rows = [];
    for (let i = 0; i < SUPPORTED_LOCALES.length; i += 2) {
      rows.push(
        SUPPORTED_LOCALES.slice(i, i + 2).map(code => ({
          text: `${code === current ? '✅ ' : ''}${LANGUAGE_NAMES[code] ?? code}`,
          callback_data: `${action}:${code}`,
        })),
      );
    }
    return rows;
  };

  async function askLanguage(userId, mode = 'connect', tgLang) {
    const t = tu(userId, tgLang);
    if (mode === 'connect' && store.inFlightPaymentCount(userId) > 0) {
      return send(userId, t('common.inflight_block_connect'));
    }
    const current = localeOf(userId, tgLang);
    const action = mode === 'connect' ? 'lg' : 'll';
    return send(userId, t('language.prompt'), {
      reply_markup: { inline_keyboard: languageRows(current, action) },
    });
  }

  async function setLanguageAndContinue(
    userId,
    messageId,
    code,
    { thenPair = false } = {},
  ) {
    const normalized = normalizeLocale(code);
    if (!SUPPORTED_LOCALES.includes(normalized)) return;
    try {
      store.setLocale?.(userId, normalized, now());
    } catch (err) {
      log.warn('setLocale failed', { err });
    }
    const t = tu(userId);
    log.info('language set', { user: log.user(userId), locale: normalized });
    if (thenPair) {
      await edit(
        userId,
        messageId,
        t('language.updated', {
          language: LANGUAGE_NAMES[normalized] ?? normalized,
        }),
      );
      return startPairing(userId);
    }
    return edit(
      userId,
      messageId,
      t('language.updated', {
        language: LANGUAGE_NAMES[normalized] ?? normalized,
      }),
      { reply_markup: { inline_keyboard: languageRows(normalized, 'll') } },
    );
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

  const walletTrouble = (r, t = tFor('en')) =>
    r.busy
      ? t('wallet.trouble_busy')
      : r.timeout
        ? t('wallet.trouble_timeout')
        : ['UNAUTHORIZED', 'RESTRICTED'].includes(r.error?.code)
          ? t('wallet.trouble_refused')
          : t('wallet.trouble_default');

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
    const from =
      update.message ??
      update.edited_message ??
      update.callback_query ??
      update.inline_query ??
      update.chosen_inline_result;
    const userId = from?.from?.id;
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
            tu(userId, from?.from?.language_code)('common.generic_error'),
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
    const t = tu(userId, msg.from.language_code);
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
        await send(msg.chat.id, t('common.group_secret_warning'));
      }
      await safe(tg.call('leaveChat', { chat_id: msg.chat.id }));
      return;
    }
    if (!allow(userId, 'update')) return send(userId, t('common.slow_down'));
    if (config.allowedUsers && !config.allowedUsers.has(userId)) {
      return send(userId, t('common.private'));
    }
    // Edits and non-text messages are only screened for secrets, never executed.
    if (update.edited_message || typeof msg.text !== 'string') {
      return hasSecret ? connect(userId, text) : undefined;
    }

    if (hasSecret) return connect(userId, text);

    const [, command, args = ''] =
      text.match(/^\/([a-z_]+)(?:@\w+)?\s*([\s\S]*)$/i) ?? [];
    switch (command?.toLowerCase()) {
      case 'start': {
        // Deep link from inline mode's "Connect your Blitz Wallet first".
        if (args.trim() === 'connect')
          return askLanguage(userId, 'connect', msg.from.language_code);
        // From the "Pay" button on an invoice someone posted in a chat.
        if (/^pay_[A-Za-z0-9_-]{1,32}$/.test(args.trim())) {
          return payPosted(userId, args.trim().slice(4));
        }
        const help = helpFor(localeOf(userId, msg.from.language_code));
        return send(
          userId,
          store.getWallet(userId) ? help : t('start.get_started', { help }),
        );
      }
      case 'help': {
        const help = helpFor(localeOf(userId, msg.from.language_code));
        return send(userId, help);
      }
      case 'connect':
        return askLanguage(userId, 'connect', msg.from.language_code);
      case 'language':
        return askLanguage(userId, 'manage', msg.from.language_code);
      case 'connect_manual':
        return send(
          userId,
          pasteHowtoFor(localeOf(userId, msg.from.language_code)),
        );
      case 'balance':
        return balance(userId);
      case 'receive':
        return receive(userId, args);
      case 'send':
        return args.trim()
          ? startSend(userId, args)
          : send(userId, t('send.paste_prompt'));
      case 'transactions':
        return transactions(userId, 0);
      case 'status':
        return status(userId);
      case 'disconnect':
        return askDisconnect(userId);
    }
    if (findInvoice(text)) return startSend(userId, text);
    return send(userId, t('common.unknown_command'));
  }

  async function onCallback(cq) {
    const userId = cq.from.id;
    const t = tu(userId, cq.from.language_code);
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
    if (m?.[1] === 'lg')
      return setLanguageAndContinue(userId, msg?.message_id, m[2], {
        thenPair: true,
      });
    if (m?.[1] === 'll')
      return setLanguageAndContinue(userId, msg?.message_id, m[2], {
        thenPair: false,
      });
    if (!m || msg?.chat?.type !== 'private' || msg.chat.id !== userId)
      return answer();
    if (config.allowedUsers && !config.allowedUsers.has(userId))
      return answer();
    if (!allow(userId, 'update')) return answer(t('common.slow_down_short'));
    const [, action, id, key] = m;
    await answer();
    switch (action) {
      case 'k':
        return keypad(userId, msg.message_id, id, key);
      case 'pc':
        return confirmPayment(userId, msg.message_id, id);
      case 'px':
        if (store.cancelPayment(id, userId, now())) pinSessions.delete(userId);
        return edit(userId, msg.message_id, t('pin.cancel_payment'));
      case 'ic':
        return checkInvoice(userId, id);
      case 'tx':
        return transactions(userId, Number(id) || 0, msg.message_id);
      case 'sr':
        return refreshStatus(userId);
      case 'dc':
        return id === 'yes'
          ? disconnect(userId, msg.message_id)
          : edit(userId, msg.message_id, t('disconnect.kept'));
    }
  }

  // ---------------------------------------------------------------- connect

  async function connect(userId, text) {
    const t = tu(userId);
    if (!allow(userId, 'wallet')) return send(userId, t('common.slow_down'));
    if (store.getWallet(userId)) {
      return send(userId, t('connect.already_connected'));
    }
    let parsed;
    try {
      parsed = parseConnectionString(text, config.allowedRelays);
    } catch (err) {
      if (!(err instanceof ConnectionStringError)) throw err;
      return send(
        userId,
        err.reason === 'relay'
          ? t('connect.relay_unsupported')
          : t('connect.invalid_string'),
      );
    }
    if (store.inFlightPaymentCount(userId) > 0) {
      return send(userId, t('common.inflight_block_connect'));
    }

    await send(userId, t('connect.checking'));
    let conn;
    try {
      conn = { ...parsed, encryption: await nwc.negotiateEncryption(parsed) };
    } catch {
      return send(userId, t('connect.relay_unreachable'));
    }
    const res = await walletCall(conn, 'get_info', {});
    if (!res.result)
      return send(
        userId,
        t('common.not_connected', { reason: walletTrouble(res, t) }),
      );
    return saveConnection(userId, conn, res.result.methods);
  }

  // Shared by both flows. `conn.secret` is the NWC client secret; it is only
  // ever written encrypted. Never silently replaces another wallet: both
  // entry points refuse while a wallet is connected, and this re-checks so a
  // pairing approval that lands after a manual connect cannot swap wallets.
  async function saveConnection(userId, conn, methods) {
    const t = tu(userId);
    const granted = Array.isArray(methods)
      ? methods.filter(m => BOT_METHODS.includes(m))
      : [];
    if (!granted.length) return send(userId, t('connect.no_methods'));

    const nowMs = now();
    if (store.getWallet(userId)) {
      return send(userId, t('connect.already_connected'));
    }
    // Confirmations and keypads belong to any previous (now impossible) state.
    store.cancelAwaiting(userId, nowMs);
    pinSessions.delete(userId);
    store.upsertWallet({
      userId,
      walletPubkey: conn.walletPubkey,
      relays: conn.relays,
      secretEnc: keyring.encrypt(conn.secret, aad(userId, conn.walletPubkey)),
      encryption: conn.encryption,
      methods: granted,
      now: nowMs,
    });
    log.info('wallet connected', {
      user: log.user(userId),
      methods: granted.join(' '),
    });

    const can = new Set(granted);
    const yes = '✅';
    const no = '—';
    const lines = [
      t('connect.connected_title'),
      t('connect.capabilities', {
        balance: can.has('get_balance') ? yes : no,
        receive: can.has('make_invoice') ? yes : no,
        transactions: can.has('list_transactions') ? yes : no,
        send: can.has('pay_invoice') && can.has('lookup_invoice') ? yes : no,
      }),
    ];
    if (can.has('pay_invoice') && !can.has('lookup_invoice')) {
      lines.push(t('connect.sending_off'));
    }
    const wid = shortWalletId(conn.walletPubkey);
    if (wid) lines.push(t('connect.wallet_id', { id: wid }));
    await send(userId, lines.join('\n'));
    if (can.has('pay_invoice') && can.has('lookup_invoice')) {
      return startPinSession(
        userId,
        { purpose: 'set' },
        t('connect.choose_pin'),
      );
    }
  }

  // ------------------------------------------------------- NWC-08 pairing

  // The bot generates the connection key itself and sends Blitz only the
  // public half in a link. Nothing secret is pasted, shown or sent through
  // Telegram, and the secret is kept in memory until Blitz approves.
  async function startPairing(userId) {
    const t = tu(userId);
    if (store.inFlightPaymentCount(userId) > 0) {
      return send(userId, t('common.inflight_block_connect'));
    }
    // Never silently switch wallets. An attacker with brief access to
    // Telegram (or whoever approves a forwarded link first) must not be able
    // to redirect future incoming payments. Switching requires an explicit
    // /disconnect first.
    if (store.getWallet(userId)) {
      return send(userId, t('connect.already_connected'));
    }
    pairings.get(userId)?.abort(); // a new link replaces the previous one
    if (pairings.size >= LIMITS.maxPendingPairings) {
      return send(userId, t('common.busy'));
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

    const abort = new AbortController();
    pairings.set(userId, abort);
    const locale = localeOf(userId);
    const body = config.connectBudgetSats
      ? t('pairing.body_with_budget', {
          budget: sats(config.connectBudgetSats * 1000, locale),
        })
      : `${t('pairing.body_no_budget')}\n${t('pairing.no_budget_warning')}`;
    // The pairing URI is NOT printed as text. It carries the pairing
    // code (state); printing it would expose it to screenshots, forwards and
    // chat history. The button alone opens Blitz.
    await send(
      userId,
      [
        t('pairing.title'),
        body,
        '',
        t('pairing.no_secret'),
        '',
        t('pairing.link_info', { minutes: LIMITS.pairingTimeoutMs / MIN }),
        '',
        t('pairing.manual_hint'),
      ].join('\n'),
      {
        reply_markup: {
          inline_keyboard: [[{ text: t('pairing.button'), url: link }]],
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
          const tt = tu(userId);
          if (store.inFlightPaymentCount(userId) > 0) {
            return send(userId, tt('pairing.approved_but_inflight'));
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
        const tt = tu(userId);
        if (err instanceof ConnectionStringError) {
          return send(userId, tt('pairing.relay_unsupported'));
        }
        if (err instanceof NwcTimeoutError) {
          return send(userId, tt('pairing.expired'));
        }
        log.error('pairing failed', { err, user: log.user(userId) });
      })
      .finally(() => pairings.get(userId) === abort && pairings.delete(userId));
  }

  // --------------------------------------------------------------- PIN pad

  const keypadMarkup = (nonce, t = tFor('en')) => ({
    inline_keyboard: [
      ['1', '2', '3'],
      ['4', '5', '6'],
      ['7', '8', '9'],
      ['b', '0', 'x'],
    ].map(row =>
      row.map(k => ({
        text: k === 'b' ? '⌫' : k === 'x' ? t('pin.cancel_button') : k,
        callback_data: `k:${nonce}:${k}`,
      })),
    ),
  });
  const dots = n => '●'.repeat(n) + '○'.repeat(LIMITS.pinLength - n);

  async function startPinSession(userId, session, prompt, messageId) {
    const t = tu(userId);
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
        reply_markup: keypadMarkup(s.nonce, t),
      });
    }
    const sent = await send(userId, text, {
      reply_markup: keypadMarkup(s.nonce, t),
    });
    s.messageId = sent?.message_id;
  }

  async function keypad(userId, messageId, nonce, key) {
    const t = tu(userId);
    const s = pinSessions.get(userId);
    if (
      !s ||
      s.nonce !== nonce ||
      s.expiresAt < now() ||
      s.messageId !== messageId
    ) {
      return edit(userId, messageId, t('pin.expired'));
    }
    if (key === 'x') {
      pinSessions.delete(userId);
      if (s.purpose === 'pay') store.cancelPayment(s.paymentId, userId, now());
      return edit(
        userId,
        messageId,
        s.purpose === 'pay' ? t('pin.cancel_payment') : t('pin.cancel_setup'),
      );
    }
    if (key === 'b') s.digits = s.digits.slice(0, -1);
    else if (key && s.digits.length < LIMITS.pinLength) s.digits += key;
    if (s.digits.length < LIMITS.pinLength) {
      return edit(
        userId,
        messageId,
        `${s.prompt}\n\n<code>${dots(s.digits.length)}</code>`,
        { reply_markup: keypadMarkup(s.nonce, t) },
      );
    }

    const pin = s.digits;
    s.digits = '';
    if (s.purpose === 'set') {
      if (isWeakPin(pin)) {
        s.prompt = t('pin.weak');
        return edit(
          userId,
          messageId,
          `${s.prompt}\n\n<code>${dots(0)}</code>`,
          { reply_markup: keypadMarkup(s.nonce, t) },
        );
      }
      Object.assign(s, {
        purpose: 'repeat',
        first: pin,
        prompt: t('pin.repeat_prompt'),
      });
      return edit(userId, messageId, `${s.prompt}\n\n<code>${dots(0)}</code>`, {
        reply_markup: keypadMarkup(s.nonce, t),
      });
    }
    if (s.purpose === 'repeat') {
      if (pin !== s.first) {
        Object.assign(s, {
          purpose: 'set',
          first: null,
          prompt: t('pin.mismatch'),
        });
        return edit(
          userId,
          messageId,
          `${s.prompt}\n\n<code>${dots(0)}</code>`,
          { reply_markup: keypadMarkup(s.nonce, t) },
        );
      }
      pinSessions.delete(userId);
      if (!store.getWallet(userId))
        return edit(userId, messageId, t('common.wallet_gone'));
      store.setPin(userId, await hashPin(pin));
      return edit(userId, messageId, t('pin.set_done'));
    }
    // purpose === 'pay'
    return finishPinForPayment(userId, messageId, s, pin);
  }

  // ---------------------------------------------------------------- sending

  async function startSend(userId, text) {
    const t = tu(userId);
    const wallet = store.getWallet(userId);
    if (!wallet) return send(userId, t('common.connect_first'));
    const can = methodsOf(wallet);
    if (!can.has('pay_invoice') || !can.has('lookup_invoice')) {
      return send(userId, t('send.not_enabled'));
    }
    if (!wallet.pin_hash) {
      return startPinSession(
        userId,
        { purpose: 'set' },
        t('pin.first_payment_prompt'),
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
          network: t('send.err_network'),
          no_amount: t('send.err_no_amount'),
          expired: t('send.err_expired'),
        }[err.reason] ?? t('send.err_invalid'),
      );
    }
    if (inv.amountMsat > config.maxPaymentSats * 1000) {
      return send(
        userId,
        t('send.over_limit', {
          max: sats(config.maxPaymentSats * 1000, localeOf(userId)),
        }),
      );
    }
    const blocking = store.blockingPaymentForHash(userId, inv.paymentHash);
    if (blocking) {
      return send(
        userId,
        blocking.status === 'paid'
          ? t('send.already_paid')
          : t('send.already_in_progress'),
      );
    }

    const nowMs = now();
    const id = randomId();
    store.cancelAwaiting(userId, nowMs);
    if (pinSessions.get(userId)?.purpose === 'pay') pinSessions.delete(userId);
    store.createPayment({
      id,
      userId,
      paymentHash: inv.paymentHash,
      invoice: inv.invoice,
      amountMsat: inv.amountMsat,
      confirmExpiresAt: Math.min(
        nowMs + LIMITS.confirmTtlMs,
        inv.expiresAt - 30_000,
      ),
      now: nowMs,
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
      : t('send.confirm_memo_none');
    return send(
      userId,
      [
        t('send.confirm_title'),
        '',
        t('send.confirm_amount', { amount: satsU(userId)(inv.amountMsat) }),
        t('send.confirm_memo', { memo }),
        t('send.confirm_expiry', {
          minutes: minutesUntil(inv.expiresAt, nowMs),
        }),
        t('send.confirm_hash', { hash: inv.paymentHash.slice(0, 16) }),
        '',
        t('send.confirm_warn'),
      ].join('\n'),
      {
        reply_markup: {
          inline_keyboard: [
            [
              { text: t('send.button_confirm'), callback_data: `pc:${id}` },
              { text: t('send.button_cancel'), callback_data: `px:${id}` },
            ],
          ],
        },
      },
    );
  }

  async function confirmPayment(userId, messageId, paymentId) {
    const t = tu(userId);
    const p = store.getPayment(paymentId, userId);
    if (
      !p ||
      p.status !== 'awaiting_confirmation' ||
      p.confirm_expires_at <= now()
    ) {
      return edit(userId, messageId, t('send.confirm_expired'));
    }
    const wallet = store.getWallet(userId);
    if (!wallet?.pin_hash)
      return edit(userId, messageId, t('common.wallet_gone'));
    if (wallet.pin_locked_until > now()) {
      return edit(
        userId,
        messageId,
        t('pin.locked_try_later', {
          minutes: minutesUntil(wallet.pin_locked_until, now()),
        }),
      );
    }
    return startPinSession(
      userId,
      { purpose: 'pay', paymentId },
      t('pin.pay_prompt', { amount: satsU(userId)(p.amount_msat) }),
      messageId,
    );
  }

  async function finishPinForPayment(userId, messageId, s, pin) {
    const t = tu(userId);
    const wallet = store.getWallet(userId);
    if (!wallet?.pin_hash) {
      pinSessions.delete(userId);
      return edit(userId, messageId, t('common.wallet_gone'));
    }
    if (wallet.pin_locked_until > now()) {
      pinSessions.delete(userId);
      store.cancelPayment(s.paymentId, userId, now());
      return edit(userId, messageId, t('pin.locked_nothing_sent'));
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
        return edit(userId, messageId, t('pin.too_many_locked'));
      }
      s.prompt =
        r.remaining === 1
          ? t('pin.wrong_remaining_one')
          : t('pin.wrong_remaining_other', { count: r.remaining });
      return edit(userId, messageId, `${s.prompt}\n\n<code>${dots(0)}</code>`, {
        reply_markup: keypadMarkup(s.nonce, t),
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
      return edit(userId, messageId, t('send.conn_unusable'));
    }
    const payment = store.getPayment(s.paymentId, userId);
    if (
      !payment?.invoice ||
      !store.claimForSubmit(s.paymentId, userId, now())
    ) {
      const busy = store.inFlightPaymentCount(userId) > 0;
      store.cancelPayment(s.paymentId, userId, now());
      return edit(
        userId,
        messageId,
        busy
          ? t('send.another_in_progress_nothing_sent')
          : t('send.expired_nothing_sent'),
      );
    }
    await edit(
      userId,
      messageId,
      t('send.sending', { amount: satsU(userId)(payment.amount_msat) }),
    );
    track(submitPayment(payment, conn));
  }

  // Sends pay_invoice exactly once. The request id and expiration are stored
  // before publishing; any outcome other than a definitive answer is
  // 'unknown' and goes to the reconciler. There is no retry path.
  async function submitPayment(payment, conn) {
    const t = tu(payment.user_id);
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
      await send(payment.user_id, t('send.submit_unknown'));
    } finally {
      submitting.delete(payment.id);
    }
  }

  function applyPaymentOutcome(payment, outcome, firstAttempt) {
    const t = tu(payment.user_id);
    const fmt = satsU(payment.user_id);
    const nowMs = now();
    const checks = firstAttempt ? 0 : payment.checks + 1;
    if (outcome.status === 'unknown') {
      const givingUp = nowMs - payment.created_at > LIMITS.unknownGiveUpMs;
      store.updatePayment(payment.id, {
        status: 'unknown',
        checks,
        nextCheckAt: givingUp
          ? null
          : nowMs + Math.min(6 * 60 * MIN, MIN * 2 ** checks),
        now: nowMs,
      });
      if (firstAttempt) {
        return track(
          send(
            payment.user_id,
            t('send.unknown_first', { amount: fmt(payment.amount_msat) }),
          ),
        );
      }
      if (givingUp && payment.next_check_at !== null) {
        return track(
          send(
            payment.user_id,
            t('send.unknown_giveup', { amount: fmt(payment.amount_msat) }),
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
        now: nowMs,
      })
    )
      return;
    if (outcome.status === 'paid') {
      // Paid a request posted through this bot: tell the requester right away
      // instead of waiting for their next scheduled check.
      const requested = store.openInvoiceByHash(payment.payment_hash);
      if (requested) track(reconcileInvoice(requested).catch(() => {}));
      const fee =
        outcome.feeMsat != null
          ? t('send.paid_fee', { fee: fmt(outcome.feeMsat) })
          : '';
      return track(
        send(
          payment.user_id,
          t('send.paid', { amount: fmt(payment.amount_msat), fee }),
        ),
      );
    }
    const why =
      {
        QUOTA_EXCEEDED: t('send.fail_QUOTA_EXCEEDED'),
        INSUFFICIENT_BALANCE: t('send.fail_INSUFFICIENT_BALANCE'),
        RESTRICTED: t('send.fail_RESTRICTED'),
        UNAUTHORIZED: t('send.fail_UNAUTHORIZED'),
        RATE_LIMITED: t('send.fail_RATE_LIMITED'),
        NOT_SENT: t('send.fail_NOT_SENT'),
      }[outcome.reason] ?? t('send.fail_default');
    return track(
      send(
        payment.user_id,
        t('send.failed', { amount: fmt(payment.amount_msat), why }),
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
    const t = tu(userId);
    const wallet = store.getWallet(userId);
    if (!wallet) return { error: t('common.connect_first') };
    if (!methodsOf(wallet).has('make_invoice')) {
      return { error: t('receive.not_enabled') };
    }
    if (store.openInvoiceCount(userId) >= LIMITS.maxOpenInvoices) {
      return {
        error: t('receive.open_cap', { max: LIMITS.maxOpenInvoices }),
      };
    }
    if (!allow(userId, 'wallet')) {
      return { error: t('common.slow_down') };
    }

    const res = await walletCall(connFor(wallet), 'make_invoice', {
      amount: amount * 1000,
      ...(memo ? { description: memo } : {}),
      expiry: LIMITS.invoiceExpirySec,
    });
    if (!res.result) return { error: walletTrouble(res, t) };
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
      return { error: t('receive.unusable') };
    }
    if (inv.amountMsat !== amount * 1000) {
      log.warn('wallet invoice amount mismatch', { user: log.user(userId) });
      return { error: t('receive.amount_mismatch') };
    }

    const nowMs = now();
    const id = randomId();
    const tracked = methodsOf(wallet).has('lookup_invoice');
    store.createInvoice({
      id,
      userId,
      paymentHash: inv.paymentHash,
      amountMsat: inv.amountMsat,
      expiresAt: inv.expiresAt,
      nextCheckAt: tracked
        ? nextInvoiceCheck(
            { created_at: nowMs, expires_at: inv.expiresAt },
            nowMs,
          )
        : null,
      ...(inlineMessageId ? { invoice: inv.invoice, inlineMessageId } : {}),
      now: nowMs,
    });
    return { inv, id, tracked };
  }

  async function receive(userId, args) {
    const t = tu(userId);
    const parsed = parseAmountMemo(args);
    if (!parsed) {
      return send(userId, t('receive.usage'));
    }
    const { inv, id, tracked, error } = await createInvoice(userId, parsed);
    if (error) return send(userId, error);
    const walletRow = store.getWallet(userId);
    const wid = walletRow ? shortWalletId(walletRow.wallet_pubkey) : null;
    await send(
      userId,
      t('receive.created', {
        amount: satsU(userId)(inv.amountMsat),
        memo: parsed.memo
          ? t('receive.created_memo', { memo: escapeHtml(parsed.memo) })
          : '',
        minutes: minutesUntil(inv.expiresAt, now()),
      }) + (wid ? `\nWallet: <code>${wid}</code>` : ''),
    );
    return send(
      userId,
      `<code>${inv.invoice}</code>`,
      tracked
        ? {
            reply_markup: {
              inline_keyboard: [
                [
                  {
                    text: t('receive.check_button'),
                    callback_data: `ic:${id}`,
                  },
                ],
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
    const t = tu(userId, q.from.language_code);
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
        text: t('inline.connect_button'),
        start_parameter: 'connect',
      });
    }
    const parsed = parseAmountMemo(q.query);
    if (!parsed) {
      return answer([], {
        text: t('inline.hint'),
        start_parameter: 'help',
      });
    }
    const memo = parsed.memo
      ? t('inline.posted_memo', { memo: escapeHtml(parsed.memo) })
      : '';
    const fmtInline = satsU(userId)(parsed.amount * 1000, q.from.language_code);
    return answer([
      {
        type: 'article',
        id: 'invoice',
        thumbnail_url: INLINE_THUMBNAIL_URL,
        thumbnail_width: 512,
        thumbnail_height: 512,
        title: t('inline.title', { amount: fmtInline }),
        description: parsed.memo || t('inline.description'),
        input_message_content: {
          message_text: t('inline.creating', {
            amount: fmtInline,
            memo,
          }),
          parse_mode: 'HTML',
        },
        // A keyboard is what makes Telegram hand us an inline_message_id to edit.
        reply_markup: {
          inline_keyboard: [
            [{ text: t('inline.creating_button'), callback_data: 'nop:0' }],
          ],
        },
      },
    ]);
  }

  async function onChosenInlineResult(r) {
    const userId = r.from.id;
    const t = tu(userId, r.from?.language_code);
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
      return editInline(t('common.private'));
    }
    // Re-parse: `query` comes from the client, nothing from the preview is trusted.
    const parsed = parseAmountMemo(r.query);
    if (!parsed) return editInline(t('inline.amount_fail'));
    const { inv, id, error } = await createInvoice(userId, parsed, {
      inlineMessageId: r.inline_message_id,
    });
    if (error) {
      // The explanation goes privately to the requester, not into the chat.
      await send(userId, error);
      return editInline(t('inline.create_fail'));
    }
    const memo = parsed.memo
      ? t('inline.posted_memo', { memo: escapeHtml(parsed.memo) })
      : '';
    // The invoice itself stays out of the message text: the buttons open it
    // in a wallet, copy it, or pay it through the bot.
    return editInline(
      t('inline.posted', {
        amount: satsU(userId)(inv.amountMsat, r.from?.language_code),
        memo,
        minutes: minutesUntil(inv.expiresAt, now()),
      }),
      invoiceButtons(inv.invoice, id, t),
    );
  }

  function invoiceButtons(invoice, id, t = tFor('en')) {
    const copy =
      invoice.length <= MAX_COPY_TEXT
        ? { text: t('inline.copy_invoice'), copy_text: { text: invoice } }
        : { text: t('inline.copy_invoice'), url: `${PAY_PAGE_URL}#${invoice}` };
    return {
      inline_keyboard: [
        [
          {
            text: t('inline.open_wallet'),
            url: `${PAY_PAGE_URL}#open:${invoice}`,
          },
          copy,
        ],
        [
          {
            text: config.botUsername
              ? t('inline.pay_with', { bot: config.botUsername })
              : t('inline.pay_generic'),
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
    const t = tu(userId, cq.from.language_code);
    if (config.allowedUsers && !config.allowedUsers.has(userId)) {
      return answer(t('common.private'));
    }
    if (!allow(userId, 'update')) return answer(t('common.slow_down_short'));
    const inv = store.getPostedInvoice(id);
    if (!inv) return answer(t('chatpay.gone'));
    if (inv.user_id === userId) return answer(t('chatpay.own'));
    if (!config.botUsername) return answer(t('chatpay.no_username'));
    return safe(
      tg.call('answerCallbackQuery', {
        callback_query_id: cq.id,
        url: `https://t.me/${config.botUsername}?start=pay_${id}`,
      }),
    );
  }

  async function payPosted(userId, id) {
    const t = tu(userId);
    const inv = store.getPostedInvoice(id);
    if (!inv) return send(userId, t('chatpay.gone_private'));
    if (inv.user_id === userId) return send(userId, t('chatpay.own_private'));
    return startSend(userId, inv.invoice);
  }

  // Returns the new status, or null if unchanged/unknown.
  async function reconcileInvoice(inv, { manual = false } = {}) {
    const t = tu(inv.user_id);
    const fmtInv = satsU(inv.user_id);
    const wallet = store.getWallet(inv.user_id);
    if (!wallet) return null;
    const nowMs = now();
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
    } else if ((r && r.state === 'expired') || nowMs > inv.expires_at) {
      status = 'expired';
    }
    const checks = inv.checks + 1;
    if (!status) {
      if (!manual)
        store.updateInvoice(inv.id, {
          status: 'open',
          checks,
          nextCheckAt: nextInvoiceCheck(inv, nowMs),
          now: nowMs,
        });
      return null;
    }
    if (
      !store.updateInvoice(inv.id, {
        status,
        checks,
        nextCheckAt: null,
        now: nowMs,
      })
    )
      return null;
    if (status === 'paid')
      track(
        send(
          inv.user_id,
          t('receive.received', { amount: fmtInv(inv.amount_msat) }),
        ),
      );
    if (inv.inline_message_id) {
      track(
        safe(
          tg.call('editMessageText', {
            inline_message_id: inv.inline_message_id,
            parse_mode: 'HTML',
            text:
              status === 'paid'
                ? t('receive.invoice_paid_inline', {
                    amount: fmtInv(inv.amount_msat),
                  })
                : t('receive.invoice_expired_inline', {
                    amount: fmtInv(inv.amount_msat),
                  }),
          }),
        ),
      );
    }
    return status;
  }

  async function checkInvoice(userId, id) {
    const t = tu(userId);
    const inv = store.getInvoice(id, userId);
    if (!inv) return send(userId, t('invoice_check.not_tracking'));
    if (inv.status !== 'open')
      return send(
        userId,
        inv.status === 'paid'
          ? t('invoice_check.paid')
          : t('invoice_check.expired'),
      );
    if (!allow(userId, 'wallet')) return send(userId, t('common.slow_down'));
    const status = await reconcileInvoice(inv, { manual: true });
    if (!status) return send(userId, t('invoice_check.not_paid'));
    if (status === 'expired') return send(userId, t('invoice_check.expired'));
  }

  // ------------------------------------------------------------- read-only

  async function balance(userId) {
    const t = tu(userId);
    const fmt = satsU(userId);
    const wallet = store.getWallet(userId);
    if (!wallet) return send(userId, t('common.connect_first'));
    if (!methodsOf(wallet).has('get_balance'))
      return send(userId, t('balance.not_enabled'));
    if (!allow(userId, 'wallet')) return send(userId, t('common.slow_down'));
    const res = await walletCall(connFor(wallet), 'get_balance', {});
    const msat = Number(res.result?.balance);
    if (!res.result || !Number.isFinite(msat) || msat < 0)
      return send(userId, walletTrouble(res, t));
    const wid = shortWalletId(wallet.wallet_pubkey);
    return send(
      userId,
      t('balance.value', { amount: fmt(msat) }) +
        (wid ? `\nWallet: <code>${wid}</code>` : ''),
    );
  }

  async function transactions(userId, page, messageId) {
    const t = tu(userId);
    const fmt = satsU(userId);
    const wallet = store.getWallet(userId);
    if (!wallet) return send(userId, t('common.connect_first'));
    if (!methodsOf(wallet).has('list_transactions'))
      return send(userId, t('transactions.not_enabled'));
    page = Math.min(Math.max(0, Math.floor(page)), LIMITS.txMaxPages - 1);
    if (!allow(userId, 'wallet')) return send(userId, t('common.slow_down'));
    const res = await walletCall(connFor(wallet), 'list_transactions', {
      limit: LIMITS.txPageSize,
      offset: page * LIMITS.txPageSize,
    });
    const list = res.result?.transactions;
    if (!Array.isArray(list)) return send(userId, walletTrouble(res, t));

    // Memos are deliberately not shown: they can hold personal details and
    // Telegram keeps chat history. They remain visible in the Blitz app.
    const lines = list.slice(0, LIMITS.txPageSize).flatMap(tx => {
      const amount = Number(tx.amount);
      if (!Number.isFinite(amount) || amount < 0) return [];
      const when = Number.isFinite(Number(tx.created_at))
        ? fmtDate(Number(tx.created_at))
        : t('transactions.unknown_date');
      const dir =
        tx.type === 'incoming'
          ? t('transactions.received')
          : t('transactions.sent');
      const fee =
        Number(tx.fees_paid) > 0 && tx.type !== 'incoming'
          ? t('transactions.fee', { fee: fmt(Number(tx.fees_paid)) })
          : '';
      const state = ['pending', 'failed', 'expired'].includes(tx.state)
        ? t('transactions.state', { state: tx.state })
        : '';
      return [`${when}  ${dir} <b>${fmt(amount)}</b> sats${fee}${state}`];
    });
    const text = lines.length
      ? `${t('transactions.title', { page: page + 1 })}\n\n${lines.join('\n')}`
      : page === 0
        ? t('transactions.empty')
        : t('transactions.empty_page');
    const nav = [];
    if (page > 0)
      nav.push({
        text: t('transactions.newer'),
        callback_data: `tx:${page - 1}`,
      });
    if (list.length >= LIMITS.txPageSize && page < LIMITS.txMaxPages - 1)
      nav.push({
        text: t('transactions.older'),
        callback_data: `tx:${page + 1}`,
      });
    const extra = nav.length
      ? { reply_markup: { inline_keyboard: [nav] } }
      : {};
    return messageId
      ? edit(userId, messageId, text, extra)
      : send(userId, text, extra);
  }

  async function status(userId) {
    const t = tu(userId);
    const fmt = satsU(userId);
    const PAY_LABEL = {
      submitting: t('status.pay_submitting'),
      unknown: t('status.pay_unknown'),
      paid: t('status.pay_paid'),
      failed: t('status.pay_failed'),
      cancelled: t('status.pay_cancelled'),
    };
    const INV_LABEL = {
      open: t('status.inv_open'),
      paid: t('status.inv_paid'),
      expired: t('status.inv_expired'),
      untracked: t('status.inv_untracked'),
    };
    if (!store.getWallet(userId))
      return send(userId, t('common.connect_first'));
    const payments = store.recentPayments(userId);
    const invoices = store.recentInvoices(userId);
    if (!payments.length && !invoices.length)
      return send(userId, t('status.nothing'));
    const lines = [];
    if (payments.length) {
      lines.push(t('status.payments_title'));
      for (const p of payments)
        lines.push(
          `${fmtDate(p.created_at / 1000)}  ${fmt(p.amount_msat)} sats  ${PAY_LABEL[p.status] ?? p.status}`,
        );
    }
    if (invoices.length) {
      lines.push('', t('status.invoices_title'));
      for (const i of invoices)
        lines.push(
          `${fmtDate(i.created_at / 1000)}  ${fmt(i.amount_msat)} sats  ${INV_LABEL[i.status] ?? i.status}`,
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
                [{ text: t('status.refresh'), callback_data: 'sr:all' }],
              ],
            },
          }
        : {},
    );
  }

  async function refreshStatus(userId) {
    const t = tu(userId);
    if (!allow(userId, 'wallet')) return send(userId, t('common.slow_down'));
    for (const p of store.recentPayments(userId))
      if (p.status === 'unknown') await reconcilePayment(p);
    for (const i of store.recentInvoices(userId))
      if (i.status === 'open') await reconcileInvoice(i, { manual: true });
    return status(userId);
  }

  // ------------------------------------------------------------- disconnect

  async function askDisconnect(userId) {
    const t = tu(userId);
    if (!store.getWallet(userId)) return send(userId, t('disconnect.none'));
    const warn =
      store.inFlightPaymentCount(userId) > 0
        ? t('disconnect.inflight_warn')
        : '';
    return send(userId, t('disconnect.prompt', { warn }), {
      reply_markup: {
        inline_keyboard: [
          [
            { text: t('disconnect.button_yes'), callback_data: 'dc:yes' },
            { text: t('disconnect.button_no'), callback_data: 'dc:no' },
          ],
        ],
      },
    });
  }

  async function disconnect(userId, messageId) {
    const t = tu(userId);
    store.deleteUser(userId);
    pinSessions.delete(userId);
    pairings.get(userId)?.abort();
    log.info('wallet disconnected', { user: log.user(userId) });
    return edit(userId, messageId, t('disconnect.done'));
  }

  // ------------------------------------------------------------ maintenance

  // Runs every ~30 s: expires confirmations, reconciles unknown payments and
  // open invoices with backoff, purges old rows, trims in-memory state.
  async function runMaintenance() {
    if (maintenanceRunning) return;
    maintenanceRunning = true;
    try {
      const nowMs = now();
      store.expireConfirmations(nowMs);
      await Promise.allSettled(
        store.duePayments(nowMs, 10).map(reconcilePayment),
      );
      await Promise.allSettled(
        store.dueInvoices(nowMs, 10).map(inv => reconcileInvoice(inv)),
      );
      store.purge(nowMs, LIMITS.retentionMs);
      for (const [userId, s] of pinSessions)
        if (s.expiresAt < nowMs) pinSessions.delete(userId);
      for (const [key, b] of buckets)
        if (nowMs - b.at > 10 * MIN) buckets.delete(key);
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
