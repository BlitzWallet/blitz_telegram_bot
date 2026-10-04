import { createHash, randomBytes } from 'node:crypto';
import { bech32 } from '@scure/base';
import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  verifyEvent,
} from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex } from 'nostr-tools/utils';
import { createBot, LIMITS } from '../src/bot.js';
import { createKeyring } from '../src/crypto.js';
import { openDb } from '../src/db.js';
import { createLogger } from '../src/log.js';
import { createNwcClient } from '../src/nwc.js';

export const RELAY = 'wss://relay.getalbypro.com/blitz';

// Fast timeouts for tests.
Object.assign(LIMITS, { readTimeoutMs: 150, payTimeoutMs: 200 });

export const sha256hex = hex =>
  createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
export const newPreimage = () => {
  const preimage = randomBytes(32).toString('hex');
  return { preimage, paymentHash: sha256hex(preimage) };
};

// Test-only BOLT11 encoder (signature is dummy; the bot leaves signature
// checks to the wallet, and the decoder does not verify it).
export function makeInvoice({
  sats,
  paymentHash,
  timestamp = Math.floor(Date.now() / 1000),
  expiry = 3600,
  description = 'test',
  prefix = 'lnbc',
}) {
  const toWords = (n, len) => {
    const w = [];
    for (let i = len - 1; i >= 0; i--) w.push(Math.floor(n / 32 ** i) % 32);
    return w;
  };
  const tag = (type, words) => [type, ...toWords(words.length, 2), ...words];
  const words = [
    ...toWords(timestamp, 7),
    ...tag(1, bech32.toWords(Buffer.from(paymentHash, 'hex'))),
    ...tag(16, bech32.toWords(randomBytes(32))),
    ...tag(13, bech32.toWords(Buffer.from(description, 'utf8'))),
    ...tag(6, toWords(expiry, 3)),
    ...bech32.toWords(Buffer.alloc(65, 1)),
  ];
  const hrp = sats == null ? prefix : `${prefix}${sats * 10}n`;
  return bech32.encode(hrp, words, false);
}

// In-memory relay + Blitz-like wallet service with real nostr crypto.
export function createFakeWallet({ encryption = 'nip44_v2' } = {}) {
  const sk = generateSecretKey();
  const pubkey = getPublicKey(sk);
  const clientSecret = bytesToHex(generateSecretKey());
  const clientPubkey = getPublicKey(Buffer.from(clientSecret, 'hex'));
  const subs = new Set();
  const requests = []; // decrypted requests seen by the wallet
  const seenIds = new Set();
  let authorized = true;
  let online = true;
  const handlers = {
    get_info: () => ({
      result: {
        methods: [
          'get_balance',
          'make_invoice',
          'lookup_invoice',
          'list_transactions',
          'pay_invoice',
        ],
      },
    }),
    get_balance: () => ({ result: { balance: 21_000_000 } }),
  };

  const emit = ev => {
    for (const s of subs) {
      const f = s.filter;
      if (f.kinds && !f.kinds.includes(ev.kind)) continue;
      if (f.authors && !f.authors.includes(ev.pubkey)) continue;
      if (f['#e'] && !ev.tags.some(t => t[0] === 'e' && f['#e'].includes(t[1])))
        continue;
      if (f['#p'] && !ev.tags.some(t => t[0] === 'p' && f['#p'].includes(t[1])))
        continue;
      s.onevent(JSON.parse(JSON.stringify(ev))); // like the wire: no cached "verified" flag
    }
  };

  const respond = (req, body, signer = sk) =>
    emit(
      finalizeEvent(
        {
          kind: 23195,
          created_at: Math.floor(Date.now() / 1000),
          tags: [
            ['p', req.pubkey],
            ['e', req.id],
          ],
          content: nip44.encrypt(
            JSON.stringify(body),
            nip44.getConversationKey(signer, req.pubkey),
          ),
        },
        signer,
      ),
    );

  const pool = {
    published: [],
    subscribe(relays, filter, { onevent }) {
      const s = { filter, onevent };
      subs.add(s);
      return { close: () => subs.delete(s) };
    },
    get: async () =>
      finalizeEvent(
        {
          kind: 13194,
          created_at: 1,
          tags: encryption ? [['encryption', encryption]] : [],
          content: Object.keys(handlers).join(' '),
        },
        sk,
      ),
    publish(relays, event) {
      pool.published.push(event);
      queueMicrotask(() => wallet.receive(event));
      return [Promise.resolve('ok')];
    },
  };

  const wallet = {
    pubkey,
    clientSecret,
    clientPubkey,
    authorizedClients: new Set([clientPubkey]),
    pool,
    // Plays Blitz's side of NWC-08: authorize the app's key and publish the
    // info event addressed to it. `overrides` lets tests forge bad variants.
    approvePairing(link, overrides = {}) {
      const url = new URL(link);
      const appKey = url.searchParams.get('pubkey') ?? url.hostname;
      const state = overrides.state ?? url.searchParams.get('state');
      const methods = overrides.methods ?? [
        ...url.searchParams.get('request_methods').split(' '),
        ...(overrides.grantOptional === false
          ? []
          : (url.searchParams.get('optional_request_methods') ?? '').split(
              ' ',
            )),
      ];
      wallet.authorizedClients.add(appKey);
      const tags = [
        ['encryption', 'nip44_v2 nip04'],
        ['p', overrides.p ?? appKey],
        ['state', state],
        ...(overrides.relays ?? [RELAY]).map(r => ['relay', r]),
      ];
      const ev = finalizeEvent(
        {
          kind: 13194,
          created_at: Math.floor(Date.now() / 1000),
          tags,
          content: methods.filter(Boolean).join(' '),
        },
        overrides.signer ?? sk,
      );
      if (overrides.tamper) ev.content += ' pay_invoice';
      emit(ev);
      return appKey;
    },
    requests,
    handlers,
    connectionString: `nostr+walletconnect://${pubkey}?relay=${encodeURIComponent(RELAY)}&secret=${clientSecret}`,
    setOnline: v => (online = v),
    revoke: () => (authorized = false),
    respond,
    sk,
    async receive(event) {
      if (!online || !verifyEvent(event) || event.kind !== 23194) return;
      if (!wallet.authorizedClients.has(event.pubkey) || !authorized) return; // Blitz drops unknown clients silently
      if (seenIds.has(event.id)) return; // event-id dedupe
      seenIds.add(event.id);
      const exp = Number(event.tags.find(t => t[0] === 'expiration')?.[1]);
      if (exp && exp <= Math.floor(Date.now() / 1000)) return;
      const req = JSON.parse(
        nip44.decrypt(
          event.content,
          nip44.getConversationKey(sk, event.pubkey),
        ),
      );
      requests.push({ ...req, event });
      const handler = handlers[req.method];
      const out = handler
        ? await handler(req.params, event)
        : { error: { code: 'NOT_IMPLEMENTED', message: 'nope' } };
      if (out === 'drop') return;
      respond(event, {
        result_type: req.method,
        error: out.error ?? null,
        result: out.result ?? null,
      });
    },
  };
  return wallet;
}

export function fakeTelegram() {
  const calls = [];
  let nextId = 100;
  return {
    calls,
    call: async (method, params = {}) => {
      calls.push({ method, params });
      if (method === 'sendMessage') return { message_id: nextId++ };
      return true;
    },
    sent: () =>
      calls
        .filter(
          c => c.method === 'sendMessage' || c.method === 'editMessageText',
        )
        .map(c => c.params.text),
    last: () =>
      calls
        .filter(
          c => c.method === 'sendMessage' || c.method === 'editMessageText',
        )
        .at(-1)?.params,
    lastText: () =>
      calls
        .filter(
          c => c.method === 'sendMessage' || c.method === 'editMessageText',
        )
        .at(-1)?.params.text,
    // Finds the newest inline button whose callback_data starts with prefix.
    button(prefix) {
      for (const c of [...calls].reverse()) {
        for (const row of c.params.reply_markup?.inline_keyboard ?? []) {
          for (const b of row)
            if (b.callback_data?.startsWith(prefix))
              return {
                data: b.callback_data,
                messageId: c.params.message_id ?? c.result,
              };
        }
      }
      return null;
    },
  };
}

export function createHarness({
  wallet = createFakeWallet(),
  config: overrides = {},
  clock,
} = {}) {
  const tg = fakeTelegram();
  // Remember the message id each sendMessage got so buttons can be "pressed".
  const origCall = tg.call;
  tg.call = async (method, params) => {
    const pending = origCall(method, params);
    const call = tg.calls.at(-1); // recorded synchronously by origCall
    const result = await pending;
    if (method === 'sendMessage')
      call.params = { ...params, message_id: result.message_id };
    return result;
  };
  const logs = [];
  const log = createLogger({
    level: 'debug',
    write: line => logs.push(line),
    pseudonymKey: Buffer.alloc(32, 7),
  });
  const store = openDb(':memory:');
  const keyring = createKeyring([{ id: 'k1', key: randomBytes(32) }]);
  const config = {
    allowedRelays: [RELAY],
    allowedUsers: null,
    maxPaymentSats: 1_000_000,
    connectBudgetSats: 100_000,
    botUsername: 'BlitzTestBot',
    ...overrides,
  };
  const nwc = createNwcClient({
    pool: wallet.pool,
    allowedRelays: config.allowedRelays,
  });
  const t = clock ?? { now: Date.now() };
  const bot = createBot({
    tg,
    store,
    nwc,
    keyring,
    config,
    log,
    now: () => t.now,
  });

  let updateId = 1;
  const h = {
    tg,
    bot,
    store,
    keyring,
    wallet,
    logs,
    clock: t,
    say: (userId, text, chat = { id: userId, type: 'private' }) =>
      bot.handleUpdate({
        update_id: updateId++,
        message: {
          message_id: updateId,
          from: { id: userId, is_bot: false },
          chat,
          text,
        },
      }),
    press: (
      userId,
      data,
      messageId = 1,
      chat = { id: userId, type: 'private' },
    ) =>
      bot.handleUpdate({
        update_id: updateId++,
        callback_query: {
          id: String(updateId),
          from: { id: userId },
          data,
          message: { message_id: messageId, chat },
        },
      }),
    async pressButton(userId, prefix) {
      const b = tg.button(prefix);
      if (!b) throw new Error(`no button ${prefix}`);
      return h.press(userId, b.data, b.messageId);
    },
    async enterPin(userId, pin) {
      const b = tg.button('k:');
      const nonce = b.data.split(':')[1];
      for (const d of pin)
        await h.press(userId, `k:${nonce}:${d}`, b.messageId);
    },
    async connect(userId, pin = '482913') {
      await h.say(userId, wallet.connectionString);
      if (pin) {
        await h.enterPin(userId, pin);
        await h.enterPin(userId, pin);
      }
    },
    // Waits for detached work (payment submission) to finish.
    settle: () => bot.drain(5000),
    allOutput: () =>
      [...logs, ...tg.calls.map(c => JSON.stringify(c.params))].join('\n'),
  };
  return h;
}
