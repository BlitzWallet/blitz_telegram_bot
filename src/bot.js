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
  // Wrong PINs are free up to pinFreeFailures; then each further one locks
  // payments for the next step, and one more after the last step turns
  // sending off until the user re-pairs (only a correct PIN resets the count).
  pinFreeFailures: 10,
  pinLocksMs: [1, 5, 15, 30, 60, 300, 1440].map(m => m * MIN),
  pinSessionMs: 5 * MIN,
  retentionMs: 7 * 24 * 60 * MIN,
  maxConcurrentWalletCalls: 100,
  maxWalletCallsPerUser: 2, // one user's dead wallet can't hold the global slots
  pairingTimeoutMs: 15 * MIN,
  // A pending link is a small record in memory; only the first
  // maxLivePairings also hold a relay subscription. The rest are confirmed
  // with the "I've approved it" button, so a flood of links can delay the
  // automatic notice but can never block pairing (M6).
  maxPendingPairings: 100_000,
  maxLivePairings: 1000,
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

// Telegram name shown on posted requests (Telegram User; first_name is required).
const displayName = from =>
  escapeHtml([from?.first_name, from?.last_name].filter(Boolean).join(' '));
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
// Localized "5 minutes" / "5 Stunden", rounded up.
const fmtDuration = (ms, locale = 'en') => {
  const m = Math.max(1, Math.ceil(ms / MIN));
  const [value, unit] = m < 60 ? [m, 'minute'] : [Math.ceil(m / 60), 'hour'];
  try {
    return new Intl.NumberFormat(locale, {
      style: 'unit',
      unit,
      unitDisplay: 'short',
    }).format(value);
  } catch {
    return `${value} ${unit}${value === 1 ? '' : 's'}`;
  }
};
// Few guesses are allowed before sending is turned off, so reject what an
// attacker would try first: repeats, sequences, keypad patterns and dates.
const COMMON_PINS = new Set([
  '147258',
  '258369',
  '369258',
  '147852',
  '159753',
  '753951',
  '789456',
  '456789',
  '102030',
  '010203',
  '000123',
  '123000',
  '520520',
  '131420',
]);
const isDate = (day, month) =>
  day >= 1 && day <= 31 && month >= 1 && month <= 12;
export const isWeakPin = pin => {
  const [a, b, c] = [0, 2, 4].map(i => Number(pin.slice(i, i + 2)));
  return (
    /^(\d)\1+$/.test(pin) ||
    /^(\d\d)\1\1$/.test(pin) || // 121212
    /^(\d{3})\1$/.test(pin) || // 123123
    /^(\d)\1(\d)\2(\d)\3$/.test(pin) || // 112233
    /^(\d)(\d)(\d)\3\2\1$/.test(pin) || // 123321
    '0123456789'.includes(pin) ||
    '9876543210'.includes(pin) ||
    COMMON_PINS.has(pin) ||
    isDate(a, b) || // DDMMYY
    isDate(b, a) || // MMDDYY
    isDate(c, b) || // YYMMDD
    /^(0[1-9]|1[0-2])(19|20)\d\d$/.test(pin) // MMYYYY
  );
};

function bucket(capacity, perMinute) {
  return { capacity, refillPerMs: perMinute / MIN };
}
const RATE = {
  update: bucket(40, 30),
  wallet: bucket(4, 8),
  pairing: bucket(3, 0.1), // 6 links/hour, so throwaway accounts churn slowly
};
// Unanswered checks back off up to 6 h.
const backoff = checks => Math.min(6 * 60 * MIN, MIN * 2 ** checks);

// Per-user text: INTRO/HELP depend on the user's language.
const introFor = lng => tFor(lng)('intro');
const helpFor = lng => tFor(lng)('help');

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
  // userId -> { abort, secret, clientPubkey, state, relays, expiresAt }
  const pairings = new Map();
  let livePairings = 0;
  let walletCalls = 0;
  const userWalletCalls = new Map(); // userId -> in-flight wallet calls
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
    b.warned = false;
    return true;
  }
  // One "slow down" per throttled burst. Replying to every throttled message
  // would let a few flooding accounts spend Telegram's global send quota that
  // payment notifications need (M6).
  function slowDown(userId, kind, reply) {
    const b = buckets.get(`${kind}:${userId}`);
    if (b.warned) return;
    b.warned = true;
    return reply();
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
      return startPairing(userId, [messageId]);
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
  // The scrypt hash is encrypted with the server key too, so a database leak
  // alone cannot be brute-forced offline (M3).
  const pinAad = wallet => `pin:${wallet.user_id}:${wallet.wallet_pubkey}`;
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
  async function withWalletSlot(userId, fn) {
    const mine = userWalletCalls.get(userId) ?? 0;
    if (
      walletCalls >= LIMITS.maxConcurrentWalletCalls ||
      mine >= LIMITS.maxWalletCallsPerUser
    )
      return { busy: true };
    walletCalls++;
    userWalletCalls.set(userId, mine + 1);
    try {
      return await fn();
    } finally {
      walletCalls--;
      const left = userWalletCalls.get(userId) - 1;
      if (left) userWalletCalls.set(userId, left);
      else userWalletCalls.delete(userId);
    }
  }

  const walletCall = (userId, conn, method, params) =>
    withWalletSlot(userId, () =>
      nwc
        .call(conn, method, params, {
          timeoutMs: LIMITS.readTimeoutMs,
          expiresInSec: LIMITS.readExpiresInSec,
        })
        .catch(err => {
          if (err instanceof NwcTimeoutError) return { timeout: true };
          throw err;
        }),
    );
  const callWallet = (wallet, method, params) =>
    walletCall(wallet.user_id, connFor(wallet), method, params);

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
    if (!allow(userId, 'update'))
      return slowDown(userId, 'update', () =>
        send(userId, t('common.slow_down')),
      );
    if (config.allowedUsers && !config.allowedUsers.has(userId)) {
      return send(userId, t('common.private'));
    }
    // Edits and non-text messages are only screened for secrets, never executed.
    if (update.edited_message || typeof msg.text !== 'string') {
      return hasSecret ? send(userId, t('connect.pasted_secret')) : undefined;
    }

    // Pasting a code is no longer a way to connect; it was only deleted above.
    if (hasSecret) return send(userId, t('connect.pasted_secret'));

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
        // Plain /start is the only place the intro runs; /help is the command
        // list. New users get a Connect button that runs the /connect flow.
        return send(
          userId,
          introFor(localeOf(userId, msg.from.language_code)),
          store.getWallet(userId)
            ? {}
            : {
                reply_markup: {
                  inline_keyboard: [
                    [{ text: t('intro_button'), callback_data: 'cn:go' }],
                  ],
                },
              },
        );
      }
      case 'help':
        return send(userId, helpFor(localeOf(userId, msg.from.language_code)));
      case 'connect':
        return askLanguage(userId, 'connect', msg.from.language_code);
      case 'language':
        return askLanguage(userId, 'manage', msg.from.language_code);
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
      case 'reconnect':
        return askReconnect(userId, msg.from.language_code);
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
    if (!m || msg?.chat?.type !== 'private' || msg.chat.id !== userId)
      return answer();
    if (config.allowedUsers && !config.allowedUsers.has(userId))
      return answer();
    if (!allow(userId, 'update'))
      return slowDown(userId, 'update', () =>
        answer(t('common.slow_down_short')),
      );
    const [, action, id, key] = m;
    // Keypad taps don't wait for the answer round trip (see drawDots).
    if (action === 'k') {
      answer();
      return keypad(userId, msg.message_id, id, key);
    }
    await answer();
    if (action === 'lg' || action === 'll')
      return setLanguageAndContinue(userId, msg.message_id, id, {
        thenPair: action === 'lg',
      });
    switch (action) {
      case 'pc':
        return confirmPayment(userId, msg.message_id, id);
      case 'px':
        if (store.cancelPayment(id, userId, now())) pinSessions.delete(userId);
        return edit(userId, msg.message_id, t('pin.cancel_payment'));
      case 'ic':
        return checkInvoice(userId, id);
      case 'tx':
        return transactions(userId, Number(id) || 0, msg.message_id);
      case 'cn':
        return askLanguage(userId, 'connect', cq.from.language_code);
      case 'sr':
        return refreshStatus(userId);
      case 'pd':
        return checkPairing(userId);
      case 'rc':
        return reconnect(userId, msg.message_id);
      case 'dc':
        return id === 'yes'
          ? disconnect(userId, msg.message_id)
          : edit(userId, msg.message_id, t('disconnect.kept'));
    }
  }

  // ---------------------------------------------------------------- connect

  // `conn.secret` is the NWC client secret; it is only ever written
  // encrypted. Never silently replaces another wallet: /connect refuses while
  // a wallet is connected, and this re-checks so a pairing approval that
  // lands late cannot swap wallets.
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
    const canPay = can.has('pay_invoice') && can.has('lookup_invoice');
    const items = [
      ['get_balance', 'can_balance'],
      ['make_invoice', 'can_receive'],
      ['list_transactions', 'can_transactions'],
    ]
      .filter(([method]) => can.has(method))
      .map(([, key]) => t(`connect.${key}`));
    if (canPay) items.push(t('connect.can_send'));
    const blocks = [t('connect.connected_title')];
    if (items.length)
      blocks.push(`${t('connect.connected_intro')}\n${items.join('\n')}`);
    if (can.has('pay_invoice') && !canPay)
      blocks.push(t('connect.sending_off'));
    else if (items.length < 4) blocks.push(t('connect.some_off'));
    await send(userId, blocks.join('\n\n'));
    if (canPay) {
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
  // setupMessageIds: earlier messages of this flow (the language prompt),
  // deleted with the link once the connection is made.
  async function startPairing(userId, setupMessageIds = []) {
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
    if (!allow(userId, 'pairing'))
      return slowDown(userId, 'pairing', () =>
        send(userId, t('common.slow_down')),
      );
    dropPairing(userId); // a new link replaces the previous one
    // Full: drop the oldest link rather than refuse everyone. With the
    // per-user pairing limit, cycling through 100k links takes a large
    // account farm, far longer than a real user needs to approve (M6).
    if (pairings.size >= LIMITS.maxPendingPairings)
      dropPairing(pairings.keys().next().value);

    const sk = generateSecretKey();
    const secret = bytesToHex(sk);
    const clientPubkey = getPublicKey(sk);
    const state = randomBytes(16).toString('hex');
    const relays = [config.allowedRelays[0]];
    const expiresAt = now() + LIMITS.pairingTimeoutMs;
    const params = [
      ['relay', relays[0]],
      ['state', state],
      [
        'name',
        config.botUsername ? `Telegram @${config.botUsername}` : 'Telegram bot',
      ],
      ['request_methods', PAIRING_METHODS],
      ['optional_request_methods', PAIRING_OPTIONAL_METHODS],
      // Blitz-specific (not NWC-08): Blitz refuses the link after this, so a
      // stale tap shows "expired" instead of creating a keyless connection.
      ['link_expires_at', String(Math.floor(expiresAt / 1000))],
      ...(config.connectBudgetSats
        ? [
            ['max_amount', String(config.connectBudgetSats * 1000)],
            ['renewal_period', 'monthly'],
          ]
        : []),
    ]
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join('&');
    const link = `${PAIRING_URL}?pubkey=${clientPubkey}&${params}`;

    const entry = {
      abort: new AbortController(),
      secret,
      clientPubkey,
      state,
      relays,
      expiresAt,
    };
    pairings.set(userId, entry);
    // The pairing URI is NOT printed as text. It carries the pairing
    // code (state); printing it would expose it to screenshots, forwards and
    // chat history. The button alone opens Blitz.
    const linkMessage = await send(
      userId,
      [
        t('pairing.title'),
        '',
        t('pairing.body'),
        '',
        t('pairing.link_info', { minutes: LIMITS.pairingTimeoutMs / MIN }),
        t('pairing.check_hint'),
      ].join('\n'),
      {
        reply_markup: {
          inline_keyboard: [
            [{ text: t('pairing.button'), url: link }],
            [{ text: t('pairing.check_button'), callback_data: 'pd:x' }],
          ],
        },
      },
    );
    entry.setupMessageIds = [
      ...setupMessageIds,
      linkMessage?.message_id,
    ].filter(Boolean);
    // Over the live limit: no subscription; the button finds the approval.
    if (livePairings >= LIMITS.maxLivePairings) return;
    livePairings++;
    entry.live = true;

    // Not tracked for shutdown: a pending link is not work in progress; the
    // completion itself runs on the user's chain, which drain() does wait for.
    nwc
      .waitForPairing(
        { clientPubkey, state, relays },
        { timeoutMs: LIMITS.pairingTimeoutMs, signal: entry.abort.signal },
      )
      .then(info =>
        runForUser(userId, () => completePairing(userId, entry, info)),
      )
      .catch(err => {
        if (entry.abort.signal.aborted) return; // replaced or completed
        const tt = tu(userId);
        if (err instanceof ConnectionStringError) {
          return send(userId, tt('pairing.relay_unsupported'));
        }
        if (err instanceof NwcTimeoutError) {
          return send(userId, tt('pairing.expired'));
        }
        log.error('pairing failed', { err, user: log.user(userId) });
      })
      .finally(() => {
        livePairings--;
        if (pairings.get(userId) === entry) pairings.delete(userId);
      });
  }

  function dropPairing(userId) {
    pairings.get(userId)?.abort.abort();
    pairings.delete(userId);
  }

  // Runs on the user's chain, from the live subscription or the button.
  async function completePairing(userId, entry, info) {
    if (pairings.get(userId) !== entry) return; // superseded meanwhile
    dropPairing(userId);
    // The link is spent; clear the setup so the chat reads "connected", then
    // PIN. Telegram only lets bots delete messages under 48 h old; the link
    // lives 15 min.
    if (entry.setupMessageIds.length)
      await safe(
        tg.call('deleteMessages', {
          chat_id: userId,
          message_ids: entry.setupMessageIds,
        }),
      );
    const t = tu(userId);
    if (store.inFlightPaymentCount(userId) > 0) {
      return send(userId, t('pairing.approved_but_inflight'));
    }
    await saveConnection(
      userId,
      {
        walletPubkey: info.walletPubkey,
        relays: info.relays,
        secret: entry.secret,
        encryption: info.encryption,
      },
      info.methods,
    );
  }

  // "I've approved it": looks the approval up once instead of relying on a
  // live subscription.
  async function checkPairing(userId) {
    const t = tu(userId);
    if (store.getWallet(userId))
      return send(userId, t('connect.already_connected'));
    const entry = pairings.get(userId);
    if (!entry || entry.expiresAt <= now()) {
      if (entry) dropPairing(userId);
      return send(userId, t('pairing.expired'));
    }
    if (!allow(userId, 'wallet')) return send(userId, t('common.slow_down'));
    let info;
    try {
      info = await withWalletSlot(userId, () => nwc.findPairing(entry));
    } catch (err) {
      if (!(err instanceof ConnectionStringError)) throw err;
      dropPairing(userId);
      return send(userId, t('pairing.relay_unsupported'));
    }
    if (info?.busy) return send(userId, t('wallet.trouble_busy'));
    if (!info) {
      const reply = await send(userId, t('pairing.not_yet'));
      if (reply?.message_id) entry.setupMessageIds.push(reply.message_id);
      return reply;
    }
    return completePairing(userId, entry, info);
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
  // Telegram sizes an inline keypad to its message bubble, so a short prompt
  // gives a narrow keypad. A line of U+2800 (blank, but not whitespace, so
  // Telegram keeps it) stretches the bubble to full width on phones.
  // ponytail: fixed count, an estimate for phone widths; tune it on real
  // devices. Too few leaves the keypad narrow, too many wraps into a second
  // blank line. Height is set by the Telegram app and can't be changed here.
  const PIN_WIDTH_PAD = '\u2800'.repeat(36);
  const pinText = (prompt, filled) =>
    `${prompt}\n\n<code>${dots(filled)}</code>\n${PIN_WIDTH_PAD}`;

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
    const text = pinText(prompt, 0);
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

  // Dot updates are cosmetic, so they don't hold the user's chain: taps are
  // counted at once, one edit is in flight per keypad, and taps that land
  // meanwhile collapse into the next edit. This also keeps fast typing under
  // Telegram's per-chat edit limit instead of queueing behind 429 waits.
  function drawDots(userId, s, t) {
    s.dirty = true;
    s.drawing ??= (async () => {
      while (s.dirty && pinSessions.get(userId) === s) {
        s.dirty = false;
        await edit(userId, s.messageId, pinText(s.prompt, s.digits.length), {
          reply_markup: keypadMarkup(s.nonce, t),
        });
      }
      s.drawing = null;
    })();
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
    if (!key) return;
    if (
      key === 'b' ||
      (key !== 'x' && s.digits.length + 1 < LIMITS.pinLength)
    ) {
      s.digits = key === 'b' ? s.digits.slice(0, -1) : s.digits + key;
      return drawDots(userId, s, t);
    }
    // Cancel or the last digit replaces the message: let a dots edit land first.
    s.dirty = false;
    await s.drawing;
    if (key === 'x') {
      pinSessions.delete(userId);
      if (s.purpose === 'pay') store.cancelPayment(s.paymentId, userId, now());
      return edit(
        userId,
        messageId,
        s.purpose === 'pay' ? t('pin.cancel_payment') : t('pin.cancel_setup'),
      );
    }
    const pin = s.digits + key;
    s.digits = '';
    if (s.purpose === 'set') {
      if (isWeakPin(pin)) {
        s.prompt = t('pin.weak');
        return edit(userId, messageId, pinText(s.prompt, 0), {
          reply_markup: keypadMarkup(s.nonce, t),
        });
      }
      Object.assign(s, {
        purpose: 'repeat',
        first: pin,
        prompt: t('pin.repeat_prompt'),
      });
      return edit(userId, messageId, pinText(s.prompt, 0), {
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
        return edit(userId, messageId, pinText(s.prompt, 0), {
          reply_markup: keypadMarkup(s.nonce, t),
        });
      }
      pinSessions.delete(userId);
      const wallet = store.getWallet(userId);
      if (!wallet) return edit(userId, messageId, t('common.wallet_gone'));
      store.setPin(userId, keyring.encrypt(await hashPin(pin), pinAad(wallet)));
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
    // No PIN means sending is off: setting one needs a fresh pairing, which
    // proves access to the Blitz app, not just to this Telegram account.
    if (!wallet.pin_hash) return send(userId, t('send.no_pin'));

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
    if (!wallet) return edit(userId, messageId, t('common.wallet_gone'));
    if (!wallet.pin_hash) return edit(userId, messageId, t('send.no_pin'));
    if (wallet.pin_locked_until > now()) {
      return edit(
        userId,
        messageId,
        t('pin.locked_try_later', {
          duration: fmtDuration(
            wallet.pin_locked_until - now(),
            localeOf(userId),
          ),
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
      store.cancelPayment(s.paymentId, userId, now());
      return edit(
        userId,
        messageId,
        t(wallet ? 'send.no_pin' : 'common.wallet_gone'),
      );
    }
    if (wallet.pin_locked_until > now()) {
      pinSessions.delete(userId);
      store.cancelPayment(s.paymentId, userId, now());
      return edit(userId, messageId, t('pin.locked_nothing_sent'));
    }
    let pinOk;
    try {
      pinOk = await verifyPin(
        pin,
        keyring.decrypt(wallet.pin_hash, pinAad(wallet)),
      );
    } catch (err) {
      log.error('cannot decrypt pin hash', { user: log.user(userId), err });
      pinSessions.delete(userId);
      store.cancelPayment(s.paymentId, userId, now());
      return edit(userId, messageId, t('common.generic_error'));
    }
    if (!pinOk) {
      const r = store.recordPinFailure(
        userId,
        now(),
        LIMITS.pinFreeFailures,
        LIMITS.pinLocksMs,
      );
      log.warn('wrong payment pin', {
        user: log.user(userId),
        failures: r.failures,
        lockedMs: r.lockMs ?? 0,
        disabled: r.disabled,
      });
      if (r.disabled || r.lockMs) {
        pinSessions.delete(userId);
        store.cancelPayment(s.paymentId, userId, now());
        return edit(
          userId,
          messageId,
          r.disabled
            ? t('pin.disabled')
            : t('pin.too_many_locked', {
                duration: fmtDuration(r.lockMs, localeOf(userId)),
              }),
        );
      }
      s.prompt =
        r.remaining === 1
          ? t('pin.wrong_remaining_one')
          : t('pin.wrong_remaining_other', { count: r.remaining });
      return edit(userId, messageId, pinText(s.prompt, 0), {
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
        nextCheckAt: givingUp ? null : nowMs + backoff(checks),
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
    const res = await callWallet(wallet, 'lookup_invoice', {
      payment_hash: payment.payment_hash,
    });
    // Busy: the wallet was never asked; check again soon without backing off.
    if (res.busy)
      return store.updatePayment(payment.id, {
        status: 'unknown',
        checks: payment.checks,
        nextCheckAt: now() + MIN,
        now: now(),
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

    const res = await callWallet(wallet, 'make_invoice', {
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
    await send(
      userId,
      t('receive.created', {
        amount: satsU(userId)(inv.amountMsat),
        memo: parsed.memo
          ? t('receive.created_memo', { memo: escapeHtml(parsed.memo) })
          : '',
        minutes: minutesUntil(inv.expiresAt, now()),
      }),
    );
    // Never paste the long code as text: it goes behind a Copy button.
    const copy =
      inv.invoice.length <= MAX_COPY_TEXT
        ? { text: t('inline.copy_invoice'), copy_text: { text: inv.invoice } }
        : {
            text: t('inline.copy_invoice'),
            url: `${PAY_PAGE_URL}#${inv.invoice}`,
          };
    const rows = [[copy]];
    if (tracked)
      rows.push([
        { text: t('receive.check_button'), callback_data: `ic:${id}` },
      ]);
    return send(userId, t('receive.copy_hint'), {
      reply_markup: { inline_keyboard: rows },
    });
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
            name: displayName(q.from),
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
    // in a wallet or pay it through the bot.
    return editInline(
      t('inline.posted', {
        name: displayName(r.from),
        amount: satsU(userId)(inv.amountMsat, r.from?.language_code),
        memo,
      }),
      invoiceButtons(inv.invoice, id, t),
    );
  }

  // The bot button needs a username to deep-link to, so without one it is
  // left off.
  function invoiceButtons(invoice, id, t = tFor('en')) {
    const rows = [
      [
        {
          text: t('inline.pay_request'),
          url: `${PAY_PAGE_URL}#open:${invoice}`,
        },
      ],
    ];
    if (config.botUsername)
      rows.push([
        {
          text: t('inline.pay_with', { bot: config.botUsername }),
          callback_data: `ip:${id}`,
        },
      ]);
    return { inline_keyboard: rows };
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
    if (!allow(userId, 'update'))
      return slowDown(userId, 'update', () =>
        answer(t('common.slow_down_short')),
      );
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
    const res = await callWallet(wallet, 'lookup_invoice', {
      payment_hash: inv.payment_hash,
    });
    // Busy: the wallet was never asked, so this says nothing about expiry.
    if (res.busy) {
      if (!manual)
        store.updateInvoice(inv.id, {
          status: 'open',
          checks: inv.checks,
          nextCheckAt: nowMs + MIN,
          now: nowMs,
        });
      return null;
    }
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
    const res = await callWallet(wallet, 'get_balance', {});
    const msat = Number(res.result?.balance);
    if (!res.result || !Number.isFinite(msat) || msat < 0)
      return send(userId, walletTrouble(res, t));
    return send(userId, t('balance.value', { amount: fmt(msat) }));
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
    const res = await callWallet(wallet, 'list_transactions', {
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
    dropPairing(userId);
    log.info('wallet disconnected', { user: log.user(userId) });
    return edit(userId, messageId, t('disconnect.done'));
  }

  // /disconnect then /connect in one step. Permissions are only read when
  // pairing, so this is how a change made in Blitz reaches the bot.
  async function askReconnect(userId, tgLang) {
    const t = tu(userId);
    if (!store.getWallet(userId)) return askLanguage(userId, 'connect', tgLang);
    // Checked before disconnecting, so the user isn't left without a wallet.
    if (store.inFlightPaymentCount(userId) > 0)
      return send(userId, t('common.inflight_block_connect'));
    return send(userId, t('reconnect.prompt'), {
      reply_markup: {
        inline_keyboard: [
          [
            { text: t('reconnect.button_yes'), callback_data: 'rc:yes' },
            { text: t('disconnect.button_no'), callback_data: 'dc:no' },
          ],
        ],
      },
    });
  }

  async function reconnect(userId, messageId) {
    const t = tu(userId);
    if (store.inFlightPaymentCount(userId) > 0)
      return edit(userId, messageId, t('common.inflight_block_connect'));
    await disconnect(userId, messageId);
    return startPairing(userId);
  }

  // ------------------------------------------------------------ maintenance

  // A row whose check throws (e.g. its key was rotated away or its relay was
  // removed from ALLOWED_RELAYS) is logged and pushed back with backoff.
  // Otherwise it stays due, and ten such rows would fill every batch and stop
  // status checks for every user (M5).
  async function checkRow(kind, row, check, retryLater) {
    try {
      await check(row);
    } catch (err) {
      log.error(`${kind} status check failed`, {
        err,
        user: log.user(row.user_id),
      });
      try {
        retryLater();
      } catch (err) {
        log.error(`${kind} reschedule failed`, { err });
      }
    }
  }

  // Runs every ~30 s: expires confirmations, reconciles unknown payments and
  // open invoices with backoff, purges old rows, trims in-memory state.
  async function runMaintenance() {
    if (maintenanceRunning) return;
    maintenanceRunning = true;
    try {
      const nowMs = now();
      store.expireConfirmations(nowMs);
      await Promise.all(
        store
          .duePayments(nowMs, 10)
          .map(p =>
            checkRow('payment', p, reconcilePayment, () =>
              applyPaymentOutcome(p, { status: 'unknown' }, false),
            ),
          ),
      );
      await Promise.all(
        store.dueInvoices(nowMs, 10).map(inv =>
          checkRow('invoice', inv, reconcileInvoice, () =>
            store.updateInvoice(inv.id, {
              status: 'open',
              checks: inv.checks + 1,
              nextCheckAt: now() + backoff(inv.checks + 1),
              now: now(),
            }),
          ),
        ),
      );
      store.purge(nowMs, LIMITS.retentionMs);
      for (const [userId, s] of pinSessions)
        if (s.expiresAt < nowMs) pinSessions.delete(userId);
      for (const [userId, p] of pairings)
        if (!p.live && p.expiresAt <= nowMs) dropPairing(userId); // live: own timer
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
