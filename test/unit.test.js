import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { createKeyring, hashPin, verifyPin } from '../src/crypto.js';
import { openDb } from '../src/db.js';
import { isWeakPin } from '../src/bot.js';
import { rotateKeys } from '../src/index.js';
import { decodeInvoice, findInvoice, isValidPreimage } from '../src/invoice.js';
import { createLogger, redact } from '../src/log.js';
import {
  ConnectionStringError,
  createNwcClient,
  NwcTimeoutError,
  parseConnectionString,
} from '../src/nwc.js';
import {
  createFakeWallet,
  makeInvoice,
  newPreimage,
  RELAY,
} from './helpers.js';

const key = () => ({ id: 'k1', key: randomBytes(32) });
const TOKEN = '123456789:AAEhBP0av28HUVnUbbbbbbbbbbbbbbbbbbbb';

// ------------------------------------------------------------------ config

test('config: valid minimal config', () => {
  const c = loadConfig({
    TELEGRAM_BOT_TOKEN: TOKEN,
    ENCRYPTION_KEYS: `k1:${randomBytes(32).toString('base64')}`,
  });
  assert.deepEqual(c.allowedRelays, [RELAY]);
  assert.equal(c.allowedUsers, null);
  assert.equal(c.maxPaymentSats, 1_000_000);
});

test('config: rejects missing/malformed secrets and unsafe values without echoing them', () => {
  const k = `k1:${randomBytes(32).toString('base64')}`;
  assert.throws(() => loadConfig({ ENCRYPTION_KEYS: k }), /TELEGRAM_BOT_TOKEN/);
  assert.throws(
    () => loadConfig({ TELEGRAM_BOT_TOKEN: 'nope', ENCRYPTION_KEYS: k }),
    /malformed/,
  );
  assert.throws(
    () => loadConfig({ TELEGRAM_BOT_TOKEN: TOKEN }),
    /ENCRYPTION_KEYS/,
  );
  assert.throws(
    () =>
      loadConfig({ TELEGRAM_BOT_TOKEN: TOKEN, ENCRYPTION_KEYS: 'k1:c2hvcnQ=' }),
    err => {
      assert.match(err.message, /32 random bytes/);
      assert.doesNotMatch(err.message, /c2hvcnQ/);
      return true;
    },
  );
  assert.throws(
    () =>
      loadConfig({
        TELEGRAM_BOT_TOKEN: TOKEN,
        ENCRYPTION_KEYS: k,
        ALLOWED_RELAYS: 'ws://10.0.0.1',
      }),
    /wss/,
  );
  assert.throws(
    () =>
      loadConfig({
        TELEGRAM_BOT_TOKEN: TOKEN,
        ENCRYPTION_KEYS: k,
        MAX_PAYMENT_SATS: '-5',
      }),
    /MAX_PAYMENT_SATS/,
  );
  assert.throws(
    () =>
      loadConfig({
        TELEGRAM_BOT_TOKEN: TOKEN,
        ENCRYPTION_KEYS: k,
        ALLOWED_TELEGRAM_USER_IDS: '@bob',
      }),
    /ALLOWED/,
  );
  assert.throws(
    () =>
      loadConfig({ TELEGRAM_BOT_TOKEN: TOKEN, ENCRYPTION_KEYS: `${k},${k}` }),
    /unique/,
  );
});

// ------------------------------------------------------------------ crypto

test('crypto: AES-GCM round trip, bound to its row, tamper-evident', () => {
  const ring = createKeyring([key()]);
  const blob = ring.encrypt('s3cret', '1:abc');
  assert.ok(blob.startsWith('v1.k1.'));
  assert.ok(!blob.includes('s3cret'));
  assert.equal(ring.decrypt(blob, '1:abc'), 's3cret');
  assert.throws(() => ring.decrypt(blob, '2:abc')); // swapped to another user
  const parts = blob.split('.');
  parts[3] = Buffer.from('x'.repeat(30)).toString('base64url');
  assert.throws(() => ring.decrypt(parts.join('.'), '1:abc'));
  assert.throws(() => createKeyring([key()]).decrypt(blob, '1:abc')); // wrong key
});

test('crypto: key rotation re-encrypts rows under the new primary key', () => {
  const old = key();
  const store = openDb(':memory:');
  const oldRing = createKeyring([old]);
  store.upsertWallet({
    userId: 7,
    walletPubkey: 'ab',
    relays: [RELAY],
    secretEnc: oldRing.encrypt('sec', '7:ab'),
    encryption: 'nip44_v2',
    methods: ['get_balance'],
    now: 1,
  });
  const ring = createKeyring([{ id: 'k2', key: randomBytes(32) }, old]);
  const log = createLogger({ write: () => {} });
  assert.equal(rotateKeys(store, ring, log), 1);
  const row = store.getWallet(7);
  assert.ok(row.secret_enc.startsWith('v1.k2.'));
  assert.equal(ring.decrypt(row.secret_enc, '7:ab'), 'sec');
  assert.equal(rotateKeys(store, ring, log), 0);

  // Key ids are matched literally ('_' is not a wildcard).
  const kx = { id: 'kx1', key: randomBytes(32) };
  store.upsertWallet({
    userId: 8,
    walletPubkey: 'cd',
    relays: [RELAY],
    secretEnc: createKeyring([kx]).encrypt('s2', '8:cd'),
    encryption: 'nip44_v2',
    methods: ['get_balance'],
    now: 1,
  });
  assert.deepEqual(
    store
      .walletsNotUnderKey('k_1')
      .map(r => r.user_id)
      .sort(),
    [7, 8],
  );
});

test('crypto: rotation encrypts legacy plain PIN hashes and re-keys encrypted ones', async () => {
  const old = key();
  const store = openDb(':memory:');
  const oldRing = createKeyring([old]);
  const hash = await hashPin('482913');
  for (const [userId, pk] of [
    [7, 'ab'],
    [8, 'cd'],
  ]) {
    store.upsertWallet({
      userId,
      walletPubkey: pk,
      relays: [RELAY],
      secretEnc: oldRing.encrypt('sec', `${userId}:${pk}`),
      encryption: 'nip44_v2',
      methods: ['pay_invoice'],
      now: 1,
    });
  }
  store.setPin(7, hash); // stored by an older version
  store.setPin(8, oldRing.encrypt(hash, 'pin:8:cd'));
  const ring = createKeyring([{ id: 'k2', key: randomBytes(32) }, old]);
  assert.equal(rotateKeys(store, ring, createLogger({ write: () => {} })), 2);
  for (const [userId, pk] of [
    [7, 'ab'],
    [8, 'cd'],
  ]) {
    const row = store.getWallet(userId);
    assert.ok(row.pin_hash.startsWith('v1.k2.'));
    assert.ok(!row.pin_hash.includes(hash.split('.')[2]), 'hash in clear');
    assert.equal(ring.decrypt(row.pin_hash, `pin:${userId}:${pk}`), hash);
  }
});

test('pin: weak PIN list rejects guessable PINs and allows random ones', () => {
  for (const pin of [
    '111111', '123456', '654321', '121212', '123123', '112233', '123321',
    '147258', '250390', '122590', '900325', '041990',
  ])
    assert.equal(isWeakPin(pin), true, pin);
  for (const pin of ['482913', '135790', '739164'])
    assert.equal(isWeakPin(pin), false, pin);
});

test('pin: failures escalate through every lock, then delete the PIN', () => {
  const store = openDb(':memory:');
  store.upsertWallet({
    userId: 7,
    walletPubkey: 'ab',
    relays: [RELAY],
    secretEnc: 'x',
    encryption: 'nip44_v2',
    methods: ['pay_invoice'],
    now: 1,
  });
  store.setPin(7, 'h');
  const locks = [10, 20];
  const results = Array.from({ length: 5 }, () =>
    store.recordPinFailure(7, 1000, 2, locks),
  );
  assert.deepEqual(results, [
    { failures: 1, remaining: 1 },
    { failures: 2, lockMs: 10 },
    { failures: 3, lockMs: 20 },
    { failures: 4, disabled: true },
    { failures: 5, disabled: true },
  ]);
  assert.equal(store.getWallet(7).pin_hash, null);
});

test('crypto: PIN hashing verifies only the right PIN', async () => {
  const h = await hashPin('482913');
  assert.ok(!h.includes('482913'));
  assert.equal(await verifyPin('482913', h), true);
  assert.equal(await verifyPin('482914', h), false);
});

// --------------------------------------------------------------------- log

test('log: redacts connection strings, invoices, hex secrets and bot tokens', () => {
  const secret = 'a'.repeat(64);
  const text = `nostr+walletconnect://${'b'.repeat(64)}?relay=x&secret=${secret} lnbc210000n1p4vyugvpp5mtln0l2f3r5pwlnxm35q90xu3z0x ${TOKEN} ${'c'.repeat(64)}`;
  const out = redact(text);
  for (const s of [
    secret,
    'lnbc210000n1',
    TOKEN,
    'c'.repeat(64),
    'walletconnect://b',
  ])
    assert.ok(!out.includes(s), s);
  const lines = [];
  const log = createLogger({ write: l => lines.push(l) });
  log.error('boom', { err: new Error(`bad ${text}`) });
  assert.ok(!lines.join().includes(secret));
});

// ----------------------------------------------------------------- invoice

test('invoice: decodes mainnet invoices and rejects bad ones', () => {
  const { paymentHash, preimage } = newPreimage();
  const inv = makeInvoice({ sats: 21000, paymentHash, description: 'coffee' });
  const d = decodeInvoice(inv);
  assert.equal(d.amountMsat, 21_000_000);
  assert.equal(d.paymentHash, paymentHash);
  assert.equal(d.description, 'coffee');
  assert.equal(
    findInvoice(`please pay lightning:${inv.toUpperCase()} thanks`),
    inv,
  );

  assert.throws(() => decodeInvoice(makeInvoice({ sats: null, paymentHash })), {
    reason: 'no_amount',
  });
  assert.throws(
    () => decodeInvoice(makeInvoice({ sats: 5, paymentHash, prefix: 'lntb' })),
    { reason: 'network' },
  );
  assert.throws(
    () =>
      decodeInvoice(
        makeInvoice({ sats: 5, paymentHash, timestamp: 1_000_000, expiry: 60 }),
      ),
    { reason: 'expired' },
  );
  assert.throws(() => decodeInvoice(inv.slice(0, -3) + 'qqq'), {
    reason: 'invalid',
  }); // bad checksum
  assert.throws(() => decodeInvoice('lnbc' + 'q'.repeat(3000)), {
    reason: 'invalid',
  });

  assert.equal(isValidPreimage(preimage, paymentHash), true);
  assert.equal(isValidPreimage('', paymentHash), false);
  assert.equal(isValidPreimage('00'.repeat(32), paymentHash), false);
});

// --------------------------------------------------------------------- nwc

test('nwc: parses connection strings strictly and enforces the relay allowlist', () => {
  const w = createFakeWallet();
  const parsed = parseConnectionString(w.connectionString, [RELAY]);
  assert.deepEqual(parsed, {
    walletPubkey: w.pubkey,
    secret: w.clientSecret,
    relays: [RELAY],
  });

  const bad = s =>
    assert.throws(
      () => parseConnectionString(s, [RELAY]),
      ConnectionStringError,
    );
  bad('hello');
  bad(`nostr+walletconnect://${w.pubkey}?relay=${RELAY}`); // no secret
  bad(`nostr+walletconnect://xyz?relay=${RELAY}&secret=${w.clientSecret}`);
  bad(
    `nostr+walletconnect://${w.pubkey}?relay=${RELAY}&secret=${'f'.repeat(64)}`,
  ); // out-of-range key
  for (const relay of [
    'ws://127.0.0.1:8080',
    'wss://169.254.169.254',
    'wss://evil.example',
  ]) {
    assert.throws(
      () =>
        parseConnectionString(
          `nostr+walletconnect://${w.pubkey}?relay=${encodeURIComponent(relay)}&secret=${w.clientSecret}`,
          [RELAY],
        ),
      { reason: 'relay' },
    );
  }
  // One allowed + one disallowed relay is still refused.
  assert.throws(
    () =>
      parseConnectionString(
        `${w.connectionString}&relay=${encodeURIComponent('wss://evil.example')}`,
        [RELAY],
      ),
    { reason: 'relay' },
  );
});

const connOf = w => ({
  walletPubkey: w.pubkey,
  secret: w.clientSecret,
  relays: [RELAY],
  encryption: 'nip44_v2',
});

test('nwc: request carries p, expiration and encryption tags and gets the wallet response', async () => {
  const w = createFakeWallet();
  const nwc = createNwcClient({ pool: w.pool, allowedRelays: [RELAY] });
  const res = await nwc.call(
    connOf(w),
    'get_balance',
    {},
    { timeoutMs: 500, expiresInSec: 30 },
  );
  assert.deepEqual(res, { result: { balance: 21_000_000 } });
  const ev = w.pool.published[0];
  assert.deepEqual(
    ev.tags.find(t => t[0] === 'p'),
    ['p', w.pubkey],
  );
  assert.deepEqual(
    ev.tags.find(t => t[0] === 'encryption'),
    ['encryption', 'nip44_v2'],
  );
  const exp = Number(ev.tags.find(t => t[0] === 'expiration')[1]);
  assert.ok(Math.abs(exp - (Date.now() / 1000 + 30)) < 3);
  assert.ok(!ev.content.includes('get_balance')); // encrypted
});

test('nwc: ignores responses not signed by the wallet, for other requests, or tampered', async () => {
  const w = createFakeWallet();
  const nwc = createNwcClient({ pool: w.pool, allowedRelays: [RELAY] });
  const { generateSecretKey } = await import('nostr-tools/pure');
  const attacker = generateSecretKey();
  w.handlers.get_balance = (params, req) => {
    // A malicious relay answers first with forged/garbled events; the real
    // wallet never answers.
    w.respond(
      req,
      { result_type: 'get_balance', result: { balance: 1 } },
      attacker,
    );
    w.respond(
      { ...req, id: 'f'.repeat(64) },
      { result_type: 'get_balance', result: { balance: 2 } },
    );
    return 'drop';
  };
  await assert.rejects(
    nwc.call(connOf(w), 'get_balance', {}, { timeoutMs: 150 }),
    NwcTimeoutError,
  );

  w.handlers.get_balance = () => ({ result: { balance: 5 } });
  const origSub = w.pool.subscribe;
  w.pool.subscribe = (relays, filter, params) =>
    origSub(relays, filter, {
      onevent: ev =>
        params.onevent({ ...ev, content: ev.content.slice(0, -4) + 'AAAA' }),
    });
  await assert.rejects(
    nwc.call(connOf(w), 'get_balance', {}, { timeoutMs: 150 }),
    NwcTimeoutError,
  );
  w.pool.subscribe = origSub;

  w.handlers.get_balance = () => ({ result: { balance: 5 } });
  assert.deepEqual(
    await nwc.call(connOf(w), 'get_balance', {}, { timeoutMs: 500 }),
    { result: { balance: 5 } },
  );
});

test('nwc: refuses to talk to relays outside the allowlist', async () => {
  const w = createFakeWallet();
  const nwc = createNwcClient({ pool: w.pool, allowedRelays: [RELAY] });
  assert.throws(
    () =>
      nwc.send(
        { ...connOf(w), relays: ['wss://evil.example'] },
        nwc.buildRequest(connOf(w), 'get_info', {}),
      ),
    /Relay not allowed/,
  );
  assert.equal(w.pool.published.length, 0);
});

test('nwc: encryption negotiation prefers nip44 and falls back to nip04 only when advertised', async () => {
  for (const [tag, expected] of [
    ['nip44_v2 nip04', 'nip44_v2'],
    ['nip04', 'nip04'],
    [null, 'nip04'],
  ]) {
    const w = createFakeWallet({ encryption: tag });
    const nwc = createNwcClient({ pool: w.pool, allowedRelays: [RELAY] });
    assert.equal(
      await nwc.negotiateEncryption({
        walletPubkey: w.pubkey,
        relays: [RELAY],
      }),
      expected,
    );
  }
  const w = createFakeWallet();
  w.pool.get = async () => null;
  const nwc = createNwcClient({ pool: w.pool, allowedRelays: [RELAY] });
  assert.equal(
    await nwc.negotiateEncryption({ walletPubkey: w.pubkey, relays: [RELAY] }),
    'nip44_v2',
  );
});
