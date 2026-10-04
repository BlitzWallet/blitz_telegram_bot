import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  classifyPayResponse,
  classifyPaymentLookup,
  LIMITS,
} from '../src/bot.js';
import { decodeInvoice } from '../src/invoice.js';
import {
  createFakeWallet,
  createHarness,
  makeInvoice,
  newPreimage,
} from './helpers.js';

const ALICE = 1001;
const BOB = 2002;
const PIN = '482913';

// Wallet that pays any invoice whose preimage it knows.
function payingWallet() {
  const w = createFakeWallet();
  w.preimages = new Map();
  w.paid = [];
  w.handlers.pay_invoice = ({ invoice }) => {
    const { paymentHash } = decodeInvoice(invoice);
    w.paid.push(paymentHash);
    return {
      result: { preimage: w.preimages.get(paymentHash), fees_paid: 2000 },
    };
  };
  return w;
}
function newInvoice(w, sats = 21000, extra = {}) {
  const { preimage, paymentHash } = newPreimage();
  w.preimages?.set(paymentHash, preimage);
  return {
    invoice: makeInvoice({ sats, paymentHash, ...extra }),
    paymentHash,
    preimage,
  };
}
async function pay(h, userId, invoice, pin = PIN) {
  await h.say(userId, invoice);
  await h.pressButton(userId, 'pc:');
  await h.enterPin(userId, pin);
  await h.settle();
}
const payRequests = w => w.requests.filter(r => r.method === 'pay_invoice');

// -------------------------------------------------------------- authorization

test('auth: unconnected user is told to connect; allowlist blocks unknown users', async () => {
  const h = createHarness();
  await h.say(ALICE, '/balance');
  assert.match(h.tg.lastText(), /Connect your wallet first/);

  const p = createHarness({ config: { allowedUsers: new Set([ALICE]) } });
  await p.say(BOB, '/balance');
  assert.equal(p.tg.lastText(), 'This bot is private.');
  await p.say(BOB, p.wallet.connectionString);
  assert.ok(
    p.tg.calls.some(c => c.method === 'deleteMessage'),
    'string deleted even for unknown users',
  );
  assert.equal(p.store.getWallet(BOB), undefined);
});

test('auth: groups are refused, connection strings there are deleted and flagged, bot leaves', async () => {
  const h = createHarness();
  const group = { id: -500, type: 'supergroup' };
  await h.say(ALICE, h.wallet.connectionString, group);
  const methods = h.tg.calls.map(c => c.method);
  assert.deepEqual(methods, ['deleteMessage', 'sendMessage', 'leaveChat']);
  assert.match(h.tg.calls[1].params.text, /treat it as exposed/);
  assert.equal(h.store.getWallet(ALICE), undefined);
  await h.say(ALICE, '/balance', group);
  assert.equal(h.wallet.requests.length, 0);
});

test('auth: callbacks from another chat or with malformed data are ignored', async () => {
  const h = createHarness();
  await h.press(ALICE, 'dc:yes', 1, { id: -5, type: 'group' });
  await h.press(ALICE, "pc:'; DROP TABLE wallets;--");
  assert.ok(h.tg.calls.every(c => c.method === 'answerCallbackQuery'));
});

// ------------------------------------------------------------------- connect

test('connect: stores only an encrypted secret, deletes the message, sets a PIN', async () => {
  const h = createHarness();
  await h.connect(ALICE);
  assert.equal(
    h.tg.calls[0].method,
    'deleteMessage',
    'deleted before anything else',
  );
  const row = h.store.getWallet(ALICE);
  assert.equal(row.wallet_pubkey, h.wallet.pubkey);
  assert.ok(!row.secret_enc.includes(h.wallet.clientSecret));
  assert.equal(
    h.keyring.decrypt(row.secret_enc, `${ALICE}:${h.wallet.pubkey}`),
    h.wallet.clientSecret,
  );
  assert.ok(row.pin_hash?.startsWith('scrypt.'));
  assert.match(h.tg.lastText(), /PIN set/);
  assert.equal(h.wallet.requests[0].method, 'get_info');
});

test('connect: invalid string, unreachable/revoked wallet and rejected connection are not stored', async () => {
  const h = createHarness();
  await h.say(ALICE, 'nostr+walletconnect://nothex?relay=x&secret=y');
  assert.match(h.tg.lastText(), /doesn’t look like a valid/);

  h.wallet.revoke(); // Blitz silently drops events from removed connections
  await h.say(ALICE, h.wallet.connectionString);
  assert.match(h.tg.lastText(), /Not connected\. Your wallet didn’t respond/);
  assert.equal(h.store.getWallet(ALICE), undefined);

  const u = createHarness();
  u.wallet.handlers.get_info = () => ({
    error: { code: 'UNAUTHORIZED', message: 'no' },
  });
  await u.say(ALICE, u.wallet.connectionString);
  assert.match(u.tg.lastText(), /refused/);
  assert.equal(u.store.getWallet(ALICE), undefined);
});

test('connect: weak and mismatched PINs are rejected', async () => {
  const h = createHarness();
  await h.say(ALICE, h.wallet.connectionString);
  await h.enterPin(ALICE, '111111');
  assert.match(h.tg.lastText(), /too easy/);
  await h.enterPin(ALICE, '482913');
  await h.enterPin(ALICE, '482914');
  assert.match(h.tg.lastText(), /didn’t match/);
  assert.equal(h.store.getWallet(ALICE).pin_hash, null);
});

test('connect: receive-only connection disables sending', async () => {
  const h = createHarness();
  h.wallet.handlers.get_info = () => ({
    result: { methods: ['get_balance', 'make_invoice', 'lookup_invoice'] },
  });
  await h.say(ALICE, h.wallet.connectionString);
  assert.ok(!h.tg.button('k:'), 'no PIN prompt without pay_invoice');
  await h.say(ALICE, newInvoice(h.wallet).invoice);
  assert.match(h.tg.lastText(), /Sending isn’t enabled/);
});

test('disconnect deletes everything; reconnect works and resets the PIN', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  await pay(h, ALICE, newInvoice(h.wallet).invoice);
  await h.say(ALICE, '/disconnect');
  await h.pressButton(ALICE, 'dc:yes');
  assert.equal(h.store.getWallet(ALICE), undefined);
  assert.equal(h.store.recentPayments(ALICE).length, 0);
  assert.match(h.tg.lastText(), /delete the Telegram connection/);
  await h.say(ALICE, '/balance');
  assert.match(h.tg.lastText(), /Connect your wallet first/);

  await h.connect(ALICE, '135790');
  assert.ok(h.store.getWallet(ALICE).pin_hash);
});

// ------------------------------------------------------------------ isolation

test('isolation: a user cannot confirm, cancel or check another user’s items', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  await h.say(ALICE, newInvoice(h.wallet).invoice);
  const confirm = h.tg.button('pc:');
  const paymentId = confirm.data.split(':')[1];

  await h.press(BOB, `pc:${paymentId}`, confirm.messageId, {
    id: BOB,
    type: 'private',
  });
  assert.match(h.tg.lastText(), /expired or was already handled/);
  await h.press(BOB, `px:${paymentId}`);
  assert.equal(
    h.store.getPayment(paymentId, ALICE).status,
    'awaiting_confirmation',
  );
  await h.press(BOB, `ic:${paymentId}`);
  assert.match(h.tg.lastText(), /no longer tracking/);
  // Bob's commands never use Alice's connection.
  await h.say(BOB, '/balance');
  assert.match(h.tg.lastText(), /Connect your wallet first/);
  assert.equal(payRequests(h.wallet).length, 0);
});

test('isolation: Bob cannot drive Alice’s PIN keypad', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  await h.say(ALICE, newInvoice(h.wallet).invoice);
  await h.pressButton(ALICE, 'pc:');
  const keypad = h.tg.button('k:');
  const nonce = keypad.data.split(':')[1];
  for (const d of PIN)
    await h.press(BOB, `k:${nonce}:${d}`, keypad.messageId, {
      id: BOB,
      type: 'private',
    });
  await h.settle();
  assert.equal(payRequests(h.wallet).length, 0);
});

// ------------------------------------------------------------------- payments

test('payment: confirm + PIN pays once and reports success', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  const { invoice, paymentHash } = newInvoice(h.wallet);
  await h.say(ALICE, invoice);
  assert.match(
    h.tg.lastText(),
    /You’re about to pay[\s\S]*21,000 sats[\s\S]*written by the recipient/,
  );
  await h.pressButton(ALICE, 'pc:');
  assert.match(h.tg.lastText(), /Enter your PIN/);
  await h.enterPin(ALICE, PIN);
  await h.settle();
  assert.deepEqual(h.wallet.paid, [paymentHash]);
  assert.match(h.tg.lastText(), /✅ Paid <b>21,000 sats<\/b> \(fee 2 sats\)/);
  const [p] = h.store.recentPayments(ALICE);
  assert.equal(p.status, 'paid');
  assert.equal(p.invoice, null, 'invoice string dropped once terminal');
  const exp = Number(
    payRequests(h.wallet)[0].event.tags.find(t => t[0] === 'expiration')[1],
  );
  assert.ok(
    exp - Date.now() / 1000 <= LIMITS.payExpiresInSec + 1,
    'pay request expires',
  );
});

test('payment: invalid, expired, amountless, testnet and over-limit invoices never reach confirmation', async () => {
  const h = createHarness({
    wallet: payingWallet(),
    config: { maxPaymentSats: 50_000 },
  });
  await h.connect(ALICE);
  const { paymentHash } = newPreimage();
  const cases = [
    ['lnbc1qqqqqqqqqqqqqqqqqqqqqqqqqq', /valid Lightning invoice/],
    [
      makeInvoice({ sats: 10, paymentHash, timestamp: 1_000_000, expiry: 60 }),
      /expired/,
    ],
    [makeInvoice({ sats: null, paymentHash }), /no amount/],
    [makeInvoice({ sats: 10, paymentHash, prefix: 'lntb' }), /mainnet/],
    [makeInvoice({ sats: 60_000, paymentHash }), /more than this bot allows/],
  ];
  for (const [text, expected] of cases) {
    await h.say(ALICE, text);
    assert.match(h.tg.lastText(), expected);
  }
  assert.equal(h.tg.button('pc:'), null);
});

test('payment: recipient memo is escaped and stripped of bidi overrides', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  await h.say(
    ALICE,
    newInvoice(h.wallet, 5, {
      description: 'refund \u202Ecod.exe <a href="x">',
    }).invoice,
  );
  assert.match(h.tg.lastText(), /refund cod\.exe &lt;a href=&quot;x&quot;&gt;/);
});

test('payment: cancel sends nothing; confirmation expires', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  await h.say(ALICE, newInvoice(h.wallet).invoice);
  await h.pressButton(ALICE, 'px:');
  assert.match(h.tg.lastText(), /cancelled\. Nothing was sent/);
  await h.pressButton(ALICE, 'pc:');
  assert.match(h.tg.lastText(), /expired or was already handled/);

  await h.say(ALICE, newInvoice(h.wallet).invoice);
  h.clock.now += LIMITS.confirmTtlMs + 1;
  await h.pressButton(ALICE, 'pc:');
  assert.match(h.tg.lastText(), /expired/);
  assert.equal(payRequests(h.wallet).length, 0);
});

test('payment: cancelling from the PIN keypad sends nothing', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  await h.say(ALICE, newInvoice(h.wallet).invoice);
  await h.pressButton(ALICE, 'pc:');
  await h.enterPin(ALICE, 'x');
  assert.match(h.tg.lastText(), /Nothing was sent/);
  assert.equal(payRequests(h.wallet).length, 0);
});

test('payment: definitive wallet error is "failed"', async () => {
  const h = createHarness({ wallet: payingWallet() });
  h.wallet.handlers.pay_invoice = () => ({
    error: { code: 'QUOTA_EXCEEDED', message: 'quota' },
  });
  await h.connect(ALICE);
  await pay(h, ALICE, newInvoice(h.wallet).invoice);
  assert.match(
    h.tg.lastText(),
    /failed\. No money left your wallet\. This would exceed the budget/,
  );
  assert.equal(h.store.recentPayments(ALICE)[0].status, 'failed');
});

test('payment: timeout is "unknown", never "failed", and is not retried', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  const { invoice } = newInvoice(h.wallet);
  h.wallet.handlers.pay_invoice = () => 'drop'; // wallet acts but the response is lost
  await pay(h, ALICE, invoice);
  assert.match(
    h.tg.lastText(),
    /couldn’t confirm[\s\S]*Don’t pay this invoice again/,
  );
  assert.equal(h.store.recentPayments(ALICE)[0].status, 'unknown');
  // Same invoice again is blocked while unknown.
  await h.say(ALICE, invoice);
  assert.match(h.tg.lastText(), /already in progress/);
  // A different invoice is blocked too: one in-flight payment per user.
  await h.say(ALICE, newInvoice(h.wallet).invoice);
  await h.pressButton(ALICE, 'pc:');
  await h.enterPin(ALICE, PIN);
  await h.settle();
  assert.match(h.tg.lastText(), /Another payment is still in progress/);
  assert.equal(payRequests(h.wallet).length, 1);
});

test('payment: INTERNAL error and result without a valid preimage are "unknown"', async () => {
  for (const handler of [
    () => ({ error: { code: 'INTERNAL', message: 'Payment status unknown' } }),
    () => ({ result: { preimage: '' } }), // Blitz does this for pending/failed sends
    () => ({ result: { preimage: '00'.repeat(32) } }),
  ]) {
    const h = createHarness({ wallet: payingWallet() });
    h.wallet.handlers.pay_invoice = handler;
    await h.connect(ALICE);
    await pay(h, ALICE, newInvoice(h.wallet).invoice);
    assert.equal(h.store.recentPayments(ALICE)[0].status, 'unknown');
  }
});

test('payment: unknown is reconciled via lookup_invoice (settled → paid)', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  const { invoice, paymentHash, preimage } = newInvoice(h.wallet);
  h.wallet.handlers.pay_invoice = () => 'drop';
  await pay(h, ALICE, invoice);
  h.wallet.handlers.lookup_invoice = ({ payment_hash }) => {
    assert.equal(payment_hash, paymentHash);
    return { result: { type: 'outgoing', state: 'pending', payment_hash } };
  };
  h.clock.now += 61_000;
  await h.bot.runMaintenance();
  assert.equal(h.store.recentPayments(ALICE)[0].status, 'unknown');
  assert.equal(h.store.recentPayments(ALICE)[0].checks, 1);

  h.wallet.handlers.lookup_invoice = ({ payment_hash }) => ({
    result: {
      type: 'outgoing',
      state: 'settled',
      preimage,
      payment_hash,
      fees_paid: 1000,
    },
  });
  h.clock.now += 3 * 60_000;
  await h.bot.runMaintenance();
  assert.equal(h.store.recentPayments(ALICE)[0].status, 'paid');
  assert.match(h.tg.lastText(), /✅ Paid/);
  assert.equal(payRequests(h.wallet).length, 1, 'never re-sent');
});

test('payment: NOT_FOUND only means "not sent" after the request expired plus grace', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  h.wallet.setOnline(false);
  await pay(h, ALICE, newInvoice(h.wallet).invoice);
  h.wallet.setOnline(true);
  h.wallet.handlers.lookup_invoice = () => ({
    error: { code: 'NOT_FOUND', message: 'nope' },
  });
  h.clock.now += 61_000; // past the first backoff, but inside expiration + grace
  await h.bot.runMaintenance();
  assert.equal(h.store.recentPayments(ALICE)[0].status, 'unknown');
  h.clock.now += LIMITS.notFoundGraceMs + LIMITS.payExpiresInSec * 1000;
  await h.bot.runMaintenance();
  assert.equal(h.store.recentPayments(ALICE)[0].status, 'failed');
  assert.match(h.tg.lastText(), /never received the request/);
});

test('payment: duplicate PIN completion / double callbacks submit only once', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  await h.say(ALICE, newInvoice(h.wallet).invoice);
  const confirm = h.tg.button('pc:');
  await h.press(ALICE, confirm.data, confirm.messageId);
  const keypad = h.tg.button('k:');
  const nonce = keypad.data.split(':')[1];
  // Replay the whole PIN sequence twice concurrently (duplicate updates).
  const taps = [...PIN, ...PIN].map(d =>
    h.press(ALICE, `k:${nonce}:${d}`, keypad.messageId),
  );
  await Promise.all(taps);
  await h.press(ALICE, confirm.data, confirm.messageId); // late duplicate confirm
  await h.settle();
  assert.equal(payRequests(h.wallet).length, 1);
});

test('payment: concurrent confirmations allow only one in flight; a newer confirmation supersedes', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  const t = h.clock.now;
  // Two awaiting rows racing for the CAS (as two processes would).
  for (const [id, hash] of [
    ['a', newPreimage().paymentHash],
    ['b', newPreimage().paymentHash],
  ]) {
    h.store.createPayment({
      id,
      userId: ALICE,
      paymentHash: hash,
      invoice: 'lnbc1x',
      amountMsat: 1000,
      confirmExpiresAt: t + 60_000,
      now: t,
    });
  }
  const wins = ['a', 'b'].filter(id => h.store.claimForSubmit(id, ALICE, t));
  assert.equal(wins.length, 1);

  const h2 = createHarness({ wallet: payingWallet() });
  await h2.connect(ALICE);
  await h2.say(ALICE, newInvoice(h2.wallet).invoice);
  const first = h2.tg.button('pc:');
  await h2.say(ALICE, newInvoice(h2.wallet).invoice);
  await h2.press(ALICE, first.data, first.messageId);
  assert.match(h2.tg.lastText(), /expired or was already handled/);
});

test('payment: same invoice cannot be paid twice; retry allowed only after definitive failure', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  const { invoice } = newInvoice(h.wallet);
  await pay(h, ALICE, invoice);
  await h.say(ALICE, invoice);
  assert.match(h.tg.lastText(), /already paid/);

  const f = newInvoice(h.wallet);
  h.wallet.handlers.pay_invoice = () => ({
    error: { code: 'INSUFFICIENT_BALANCE', message: 'x' },
  });
  await pay(h, ALICE, f.invoice);
  await h.say(ALICE, f.invoice);
  assert.ok(h.tg.button('pc:'), 'can try again after a definitive failure');
});

test('payment: restart during payment resumes as unknown and reconciles', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  await h.say(ALICE, newInvoice(h.wallet).invoice);
  const id = h.tg.button('pc:').data.split(':')[1];
  // Simulate a crash right after the CAS: row is 'submitting', nothing published.
  assert.equal(h.store.claimForSubmit(id, ALICE, h.clock.now), true);
  assert.equal(h.store.recoverSubmitting(h.clock.now), 1); // what startup does
  h.wallet.handlers.lookup_invoice = () => ({
    error: { code: 'NOT_FOUND', message: '' },
  });
  await h.bot.runMaintenance();
  assert.equal(
    h.store.getPayment(id, ALICE).status,
    'unknown',
    'too early to call it',
  );
  h.clock.now += LIMITS.notFoundGraceMs + 2 * 60_000;
  await h.bot.runMaintenance();
  assert.equal(h.store.getPayment(id, ALICE).status, 'failed');
  assert.equal(
    payRequests(h.wallet).length,
    0,
    'recovery never sends pay_invoice',
  );

  // And a crash after the wallet paid: reconciler finds it settled.
  const h2 = createHarness({ wallet: payingWallet() });
  await h2.connect(ALICE);
  const inv2 = newInvoice(h2.wallet);
  await h2.say(ALICE, inv2.invoice);
  const id2 = h2.tg.button('pc:').data.split(':')[1];
  h2.store.claimForSubmit(id2, ALICE, h2.clock.now);
  h2.store.recoverSubmitting(h2.clock.now);
  h2.wallet.handlers.lookup_invoice = () => ({
    result: {
      type: 'outgoing',
      state: 'settled',
      preimage: inv2.preimage,
      payment_hash: inv2.paymentHash,
    },
  });
  await h2.bot.runMaintenance();
  assert.equal(h2.store.getPayment(id2, ALICE).status, 'paid');
});

test('payment: wrong PINs lock payments and cancel the attempt', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  await h.say(ALICE, newInvoice(h.wallet).invoice);
  await h.pressButton(ALICE, 'pc:');
  for (let i = 0; i < LIMITS.pinMaxFailures - 1; i++) {
    h.clock.now += 60_000; // keep the per-user update rate limit out of the way
    await h.enterPin(ALICE, '000001');
    assert.match(h.tg.lastText(), /Wrong PIN/);
  }
  await h.enterPin(ALICE, '000001');
  assert.match(h.tg.lastText(), /locked for 1 hour/);
  await h.say(ALICE, newInvoice(h.wallet).invoice);
  await h.pressButton(ALICE, 'pc:');
  assert.match(h.tg.lastText(), /locked/);
  assert.equal(payRequests(h.wallet).length, 0);
  h.clock.now += LIMITS.pinLockMs + 1;
  await pay(
    h,
    ALICE,
    newInvoice(h.wallet, 21000, { timestamp: Math.floor(h.clock.now / 1000) })
      .invoice,
  );
  assert.equal(payRequests(h.wallet).length, 1);
});

test('payment: revoked connection reports a clear, non-failed state', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  h.wallet.revoke();
  await pay(h, ALICE, newInvoice(h.wallet).invoice);
  assert.equal(h.store.recentPayments(ALICE)[0].status, 'unknown');
  await h.say(ALICE, '/balance');
  assert.match(h.tg.lastText(), /didn’t respond[\s\S]*still exists/);
});

test('classifiers: pure state mapping', () => {
  const { preimage, paymentHash } = newPreimage();
  assert.equal(
    classifyPayResponse({ result: { preimage } }, paymentHash).status,
    'paid',
  );
  assert.equal(
    classifyPayResponse({ error: { code: 'PAYMENT_FAILED' } }, paymentHash)
      .status,
    'failed',
  );
  assert.equal(
    classifyPayResponse({ error: { code: 'OTHER' } }, paymentHash).status,
    'unknown',
  );
  assert.equal(classifyPayResponse(undefined, paymentHash).status, 'unknown');
  const p = {
    payment_hash: paymentHash,
    request_expires_at: 1_000_000,
    updated_at: 0,
  };
  assert.equal(
    classifyPaymentLookup(
      { result: { type: 'incoming', state: 'settled' } },
      p,
      0,
    ).status,
    'unknown',
  );
  assert.equal(
    classifyPaymentLookup({ result: { state: 'failed' } }, p, 0).status,
    'failed',
  );
  assert.equal(
    classifyPaymentLookup({ timeout: true }, p, 9e12).status,
    'unknown',
  );
});

// ------------------------------------------------------------------ invoices

function invoicingWallet() {
  const w = payingWallet();
  w.made = [];
  w.handlers.make_invoice = ({ amount, description, expiry }) => {
    const { preimage, paymentHash } = newPreimage();
    w.made.push({ amount, description, expiry, preimage, paymentHash });
    return {
      result: {
        invoice: makeInvoice({
          sats: amount / 1000,
          paymentHash,
          expiry,
          description: description ?? '',
        }),
      },
    };
  };
  return w;
}

test('receive: creates an invoice, tracks it, notifies when paid', async () => {
  const h = createHarness({ wallet: invoicingWallet() });
  await h.connect(ALICE);
  await h.say(ALICE, '/receive 21,000 coffee <b>');
  const made = h.wallet.made[0];
  assert.deepEqual(
    [made.amount, made.description, made.expiry],
    [21_000_000, 'coffee <b>', 3600],
  );
  assert.match(h.tg.sent().at(-2), /21,000 sats<\/b> \(coffee &lt;b&gt;\)/);
  assert.match(h.tg.lastText(), /^<code>lnbc/);

  h.wallet.handlers.lookup_invoice = () => ({
    result: { type: 'incoming', state: 'pending' },
  });
  await h.pressButton(ALICE, 'ic:');
  assert.equal(h.tg.lastText(), 'Not paid yet.');

  h.wallet.handlers.lookup_invoice = () => ({
    result: { type: 'incoming', state: 'settled', preimage: made.preimage },
  });
  h.clock.now += 61_000;
  await h.bot.runMaintenance();
  assert.match(h.tg.lastText(), /💰 Received <b>21,000 sats/);
  assert.equal(h.store.recentInvoices(ALICE)[0].status, 'paid');
});

test('receive: invoice expires unpaid; wallet invoice with wrong amount is refused', async () => {
  const h = createHarness({ wallet: invoicingWallet() });
  await h.connect(ALICE);
  await h.say(ALICE, '/receive 1000');
  h.wallet.handlers.lookup_invoice = () => ({
    error: { code: 'NOT_FOUND', message: '' },
  });
  h.clock.now += 3600_000 + 61_000;
  await h.bot.runMaintenance();
  assert.equal(h.store.recentInvoices(ALICE)[0].status, 'expired');

  h.wallet.handlers.make_invoice = () => ({
    result: {
      invoice: makeInvoice({
        sats: 999_999,
        paymentHash: newPreimage().paymentHash,
      }),
    },
  });
  h.clock.now = Date.now();
  await h.say(ALICE, '/receive 1000');
  assert.match(h.tg.lastText(), /different amount/);
});

test('receive: usage errors and open-invoice cap', async () => {
  const h = createHarness({ wallet: invoicingWallet() });
  await h.connect(ALICE);
  for (const bad of [
    '/receive',
    '/receive abc',
    '/receive 0',
    '/receive 100000001',
  ]) {
    await h.say(ALICE, bad);
    assert.match(h.tg.lastText(), /Usage/);
  }
  for (let i = 0; i < LIMITS.maxOpenInvoices; i++) {
    h.clock.now += 60_000; // stay under the wallet rate limit
    await h.say(ALICE, '/receive 10');
  }
  await h.say(ALICE, '/receive 10');
  assert.match(h.tg.lastText(), /already have 5 open invoices/);
});

// ------------------------------------------------------------ balance & history

test('balance: shows Wallet Connect balance in sats', async () => {
  const h = createHarness();
  await h.connect(ALICE);
  await h.say(ALICE, '/balance');
  assert.equal(h.tg.lastText(), 'Wallet Connect balance: <b>21,000 sats</b>');
});

test('transactions: pagination, empty history, no memos shown', async () => {
  const h = createHarness();
  const tx = i => ({
    type: i % 2 ? 'incoming' : 'outgoing',
    amount: 1000 * (i + 1),
    fees_paid: 1000,
    created_at: 1_700_000_000 + i,
    description: `secret memo ${i}`,
  });
  const all = Array.from({ length: 13 }, (_, i) => tx(i));
  h.wallet.handlers.list_transactions = ({ limit, offset }) => ({
    result: { transactions: all.slice(offset, offset + limit) },
  });
  await h.connect(ALICE);
  await h.say(ALICE, '/transactions');
  assert.match(h.tg.lastText(), /page 1/);
  assert.doesNotMatch(h.tg.lastText(), /secret memo/);
  assert.ok(h.tg.button('tx:1'));
  await h.pressButton(ALICE, 'tx:1');
  assert.match(h.tg.lastText(), /page 2/);
  assert.equal(h.tg.lastText().split('\n').length, 2 + 3);
  assert.deepEqual(
    h.wallet.requests
      .filter(r => r.method === 'list_transactions')
      .map(r => r.params),
    [
      { limit: 10, offset: 0 },
      { limit: 10, offset: 10 },
    ],
  );

  const e = createHarness();
  e.wallet.handlers.list_transactions = () => ({
    result: { transactions: [] },
  });
  await e.connect(ALICE);
  await e.say(ALICE, '/transactions');
  assert.equal(e.tg.lastText(), 'No transactions yet.');
});

// ------------------------------------------------------------------- security

test('security: credentials never appear in logs or anything sent to Telegram', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  await pay(h, ALICE, newInvoice(h.wallet).invoice);
  await h.say(ALICE, h.wallet.connectionString + 'garbage'); // malformed string too
  await h.say(ALICE, '/balance');
  const out = h.allOutput();
  assert.ok(!out.includes(h.wallet.clientSecret), 'secret leaked');
  assert.ok(!out.includes('nostr+walletconnect'), 'connection string leaked');
  assert.ok(!out.includes(PIN), 'PIN leaked');
  assert.ok(!h.logs.join().includes(String(ALICE)), 'raw Telegram id in logs');
});

test('security: unexpected errors give a generic reply', async () => {
  const h = createHarness();
  await h.connect(ALICE);
  h.store.getWallet = () => {
    throw new Error(`db exploded ${h.wallet.clientSecret}`);
  };
  await h.say(ALICE, '/balance');
  assert.equal(
    h.tg.lastText(),
    'Something went wrong on my side. Please try again.',
  );
  assert.ok(!h.allOutput().includes(h.wallet.clientSecret));
});

test('security: rate limiting caps wallet requests per user', async () => {
  const h = createHarness();
  await h.connect(ALICE);
  h.clock.now += 60_000; // refill after connecting
  for (let i = 0; i < 5; i++) await h.say(ALICE, '/balance');
  assert.match(h.tg.lastText(), /Slow down/);
  assert.equal(
    h.wallet.requests.filter(r => r.method === 'get_balance').length,
    4,
  );
  // Other users are unaffected.
  await h.say(BOB, '/balance');
  assert.match(h.tg.lastText(), /Connect your wallet first/);
});

test('security: unknown commands are not executed', async () => {
  const h = createHarness();
  await h.connect(ALICE);
  const before = h.wallet.requests.length;
  await h.say(ALICE, '/pay_everything');
  await h.say(ALICE, 'rm -rf / ; $(curl evil)');
  assert.match(h.tg.lastText(), /didn’t understand/);
  assert.equal(h.wallet.requests.length, before);
});

test('security: connection strings in edits and captions are deleted; edits never run commands', async () => {
  const h = createHarness();
  await h.bot.handleUpdate({
    update_id: 900,
    edited_message: {
      message_id: 77,
      from: { id: ALICE },
      chat: { id: ALICE, type: 'private' },
      text: `oops ${h.wallet.connectionString}`,
    },
  });
  assert.deepEqual(h.tg.calls[0], {
    method: 'deleteMessage',
    params: { chat_id: ALICE, message_id: 77 },
  });
  await h.bot.handleUpdate({
    update_id: 901,
    message: {
      message_id: 78,
      from: { id: BOB },
      chat: { id: BOB, type: 'private' },
      caption: h.wallet.connectionString,
    },
  });
  assert.ok(
    h.tg.calls.some(
      c => c.method === 'deleteMessage' && c.params.message_id === 78,
    ),
  );
  await h.bot.handleUpdate({
    update_id: 902,
    edited_message: {
      message_id: 79,
      from: { id: ALICE },
      chat: { id: ALICE, type: 'private' },
      text: '/balance',
    },
  });
  assert.equal(
    h.wallet.requests.filter(r => r.method === 'get_balance').length,
    0,
  );
});

// ------------------------------------------------------------- NWC-08 pairing

function findUrlButton(h) {
  for (const c of [...h.tg.calls].reverse()) {
    for (const row of c.params.reply_markup?.inline_keyboard ?? []) {
      for (const b of row) if (b.url) return b.url;
    }
  }
  return null;
}
const settlePairing = h =>
  new Promise(r => setTimeout(r, 20)).then(() => h.settle());

test('pairing: link carries only public data and the requested limits', async () => {
  const h = createHarness();
  await h.say(ALICE, '/connect');
  const link = new URL(findUrlButton(h));
  assert.equal(link.origin + link.pathname, 'https://blitzwallet.app/nwc/auth');
  const p = link.searchParams;
  assert.match(p.get('pubkey'), /^[0-9a-f]{64}$/);
  assert.match(p.get('state'), /^[0-9a-f]{32}$/);
  assert.equal(p.get('relay'), 'wss://relay.getalbypro.com/blitz');
  assert.equal(p.get('name'), 'Telegram @BlitzTestBot');
  assert.equal(
    p.get('request_methods'),
    'get_info get_balance make_invoice lookup_invoice list_transactions',
  );
  assert.equal(p.get('optional_request_methods'), 'pay_invoice');
  assert.equal(p.get('max_amount'), '100000000');
  assert.equal(p.get('renewal_period'), 'daily');
  assert.ok(!link.href.includes('secret'));
  assert.ok(findUrlButton(h).includes('%20'), 'spaces are %20-encoded, not +');
  assert.match(h.tg.lastText(), /<code>nostr\+walletauth:\/\/[0-9a-f]{64}\?/);
});

test('pairing: approval stores the connection; the secret never leaves the bot', async () => {
  const h = createHarness();
  await h.say(ALICE, '/connect');
  const appKey = h.wallet.approvePairing(findUrlButton(h));
  await settlePairing(h);
  const row = h.store.getWallet(ALICE);
  assert.equal(row.wallet_pubkey, h.wallet.pubkey);
  assert.equal(row.encryption, 'nip44_v2');
  const secret = h.keyring.decrypt(
    row.secret_enc,
    `${ALICE}:${h.wallet.pubkey}`,
  );
  const { getPublicKey } = await import('nostr-tools/pure');
  assert.equal(getPublicKey(Buffer.from(secret, 'hex')), appKey);
  assert.ok(
    !h.allOutput().includes(secret),
    'secret leaked to Telegram or logs',
  );
  assert.match(h.tg.lastText(), /payment PIN/);

  await h.enterPin(ALICE, PIN);
  await h.enterPin(ALICE, PIN);
  await h.say(ALICE, '/balance');
  assert.equal(h.tg.lastText(), 'Wallet Connect balance: <b>21,000 sats</b>');
  assert.equal(h.wallet.requests.at(-1).event.pubkey, appKey);
});

test('pairing: receive-only approval skips the PIN and disables sending', async () => {
  const h = createHarness();
  await h.say(ALICE, '/connect');
  h.wallet.approvePairing(findUrlButton(h), { grantOptional: false });
  await settlePairing(h);
  assert.ok(h.store.getWallet(ALICE));
  assert.ok(!h.store.getWallet(ALICE).methods.includes('pay_invoice'));
  assert.ok(!h.tg.button('k:'), 'no PIN prompt');
});

test('pairing: wrong state, wrong recipient or a forged signature are ignored', async () => {
  // NWC-08 learns the wallet key from the signer, so `state` (only in the link)
  // is what stops a stranger's wallet answering first; signatures stop forgery.
  for (const overrides of [
    { state: 'ab'.repeat(16) },
    { p: 'cd'.repeat(32) },
    { tamper: true },
  ]) {
    const h = createHarness();
    await h.say(ALICE, '/connect');
    h.wallet.approvePairing(findUrlButton(h), overrides);
    await settlePairing(h);
    assert.equal(
      h.store.getWallet(ALICE),
      undefined,
      JSON.stringify(Object.keys(overrides)),
    );
  }
});

test('pairing: a relay outside the allowlist is refused', async () => {
  const h = createHarness();
  await h.say(ALICE, '/connect');
  h.wallet.approvePairing(findUrlButton(h), { relays: ['wss://evil.example'] });
  await settlePairing(h);
  assert.equal(h.store.getWallet(ALICE), undefined);
  assert.match(h.tg.lastText(), /relay this bot doesn’t support/);
});

test('pairing: a newer link replaces the old one; disconnect cancels it', async () => {
  const h = createHarness();
  await h.say(ALICE, '/connect');
  const first = findUrlButton(h);
  await h.say(ALICE, '/connect');
  h.wallet.approvePairing(first);
  await settlePairing(h);
  assert.equal(
    h.store.getWallet(ALICE),
    undefined,
    'old link must not connect',
  );

  const second = findUrlButton(h);
  await h.say(ALICE, '/disconnect'); // nothing connected yet
  h.wallet.approvePairing(second);
  await settlePairing(h);
  assert.ok(h.store.getWallet(ALICE), 'current link still works');
});

test('pairing: link expires', async () => {
  const saved = LIMITS.pairingTimeoutMs;
  LIMITS.pairingTimeoutMs = 50;
  try {
    const h = createHarness();
    await h.say(ALICE, '/connect');
    const link = findUrlButton(h);
    await new Promise(r => setTimeout(r, 80));
    await h.settle();
    assert.match(h.tg.lastText(), /link expired/);
    h.wallet.approvePairing(link);
    await settlePairing(h);
    assert.equal(h.store.getWallet(ALICE), undefined);
  } finally {
    LIMITS.pairingTimeoutMs = saved;
  }
});

test('pairing: never switches connections while a payment is unconfirmed', async () => {
  const h = createHarness({ wallet: payingWallet() });
  await h.connect(ALICE);
  h.wallet.handlers.pay_invoice = () => 'drop';
  await pay(h, ALICE, newInvoice(h.wallet).invoice);
  const before = h.store.getWallet(ALICE).secret_enc;
  await h.say(ALICE, '/connect');
  assert.match(h.tg.lastText(), /payment is still being confirmed/);
  assert.equal(findUrlButton(h), null);
  assert.equal(h.store.getWallet(ALICE).secret_enc, before);
});

test('pairing: the manual paste flow is still available', async () => {
  const h = createHarness();
  await h.say(ALICE, '/connect_manual');
  assert.match(h.tg.lastText(), /Connect manually/);
});

// ---------------------------------------------------------------- inline mode

const inlineQuery = (h, userId, query) =>
  h.bot.handleUpdate({
    update_id: 5000,
    inline_query: { id: `q${query}`, from: { id: userId }, query, offset: '' },
  });
const chooseInline = (h, userId, query, inlineMessageId = 'imid-1') =>
  h.bot.handleUpdate({
    update_id: 5001,
    chosen_inline_result: {
      result_id: 'invoice',
      from: { id: userId },
      query,
      inline_message_id: inlineMessageId,
    },
  });
const lastInlineAnswer = h =>
  h.tg.calls.filter(c => c.method === 'answerInlineQuery').at(-1).params;
const lastInlineEdit = h =>
  h.tg.calls
    .filter(c => c.method === 'editMessageText' && c.params.inline_message_id)
    .at(-1)?.params;

test('inline: unconnected users get a connect shortcut, never cached', async () => {
  const h = createHarness();
  await inlineQuery(h, ALICE, '5000 pizza');
  const a = lastInlineAnswer(h);
  assert.deepEqual(a.results, []);
  assert.deepEqual(a.button, {
    text: 'Connect your Blitz Wallet first',
    start_parameter: 'connect',
  });
  assert.equal(a.is_personal, true);
  assert.equal(a.cache_time, 0);
  await h.say(ALICE, '/start connect');
  assert.ok(
    findUrlButton(h)?.startsWith('https://blitzwallet.app/nwc/auth'),
    '/start connect starts pairing',
  );
});

test('inline: typing previews without touching the wallet', async () => {
  const h = createHarness();
  h.wallet.handlers.make_invoice = () => assert.fail('no invoice while typing');
  await h.connect(ALICE);
  const before = h.wallet.requests.length;
  for (const q of ['5', '50', '5000', '5000 pi', '5000 pizza <b>'])
    await inlineQuery(h, ALICE, q);
  assert.equal(h.wallet.requests.length, before);
  const [result] = lastInlineAnswer(h).results;
  assert.equal(result.title, 'Request 5,000 sats');
  assert.match(
    result.input_message_content.message_text,
    /5,000 sats<\/b> requested — pizza &lt;b&gt;/,
  );
  assert.ok(
    result.reply_markup.inline_keyboard[0][0],
    'keyboard needed to get an inline_message_id',
  );

  await inlineQuery(h, ALICE, 'pizza');
  assert.deepEqual(lastInlineAnswer(h).results, []);
  assert.equal(lastInlineAnswer(h).button.start_parameter, 'help');
});

test('inline: choosing the result creates one invoice, edits the message, notifies when paid', async () => {
  const h = createHarness();
  const made = [];
  h.wallet.handlers.make_invoice = ({ amount, description, expiry }) => {
    const { preimage, paymentHash } = newPreimage();
    made.push({ amount, description, preimage });
    return {
      result: {
        invoice: makeInvoice({
          sats: amount / 1000,
          paymentHash,
          expiry,
          description,
        }),
      },
    };
  };
  await h.connect(ALICE);
  await chooseInline(h, ALICE, '5000 pizza');
  assert.deepEqual(
    made.map(m => [m.amount, m.description]),
    [[5_000_000, 'pizza']],
  );
  const edit = lastInlineEdit(h);
  assert.equal(edit.inline_message_id, 'imid-1');
  assert.equal(
    edit.text,
    '⚡ <b>5,000 sats</b> requested — pizza\nExpires in 60 min.',
  );
  assert.ok(!edit.text.includes('lnbc'), 'invoice is not shown in the chat');
  const [[open, copy], [pay]] = edit.reply_markup.inline_keyboard;
  const invoice = open.url.split('#open:')[1];
  assert.match(invoice, /^lnbc50000n1/);
  assert.equal(open.url, `https://blitzwalletapp.com/pay#open:${invoice}`);
  assert.equal(open.text, '⚡ Open wallet');
  // Short enough: Telegram's native copy button; longer: the pay page.
  assert.ok(invoice.length <= 256);
  assert.deepEqual(copy, {
    text: '📋 Copy invoice',
    copy_text: { text: invoice },
  });
  assert.equal(pay.text, 'Pay with @BlitzTestBot');
  assert.match(pay.callback_data, /^ip:/);
  assert.equal(h.store.recentInvoices(ALICE)[0].status, 'open');

  h.wallet.handlers.lookup_invoice = () => ({
    result: { type: 'incoming', state: 'settled', preimage: made[0].preimage },
  });
  h.clock.now += 61_000;
  await h.bot.runMaintenance();
  const dms = h.tg.calls.filter(
    c => c.method === 'sendMessage' && c.params.chat_id === ALICE,
  );
  assert.match(dms.at(-1).params.text, /💰 Received <b>5,000 sats/);
  assert.match(lastInlineEdit(h).text, /✅ <b>5,000 sats<\/b> paid/);
});

test('inline: long invoices copy through the pay page; results show the Blitz icon', async () => {
  const h = createHarness();
  h.wallet.handlers.make_invoice = ({ amount }) => ({
    result: {
      invoice: makeInvoice({
        sats: amount / 1000,
        paymentHash: newPreimage().paymentHash,
        description: 'x'.repeat(200),
      }),
    },
  });
  await h.connect(ALICE);
  await inlineQuery(h, ALICE, '5000');
  const [result] = lastInlineAnswer(h).results;
  assert.equal(
    result.thumbnail_url,
    'https://blitzwalletapp.com/public/favicon/web-app-manifest-512x512.png',
  );
  await chooseInline(h, ALICE, '5000');
  const [[open, copy]] = lastInlineEdit(h).reply_markup.inline_keyboard;
  const invoice = open.url.split('#open:')[1];
  assert.ok(invoice.length > 256);
  assert.deepEqual(copy, {
    text: '📋 Copy invoice',
    url: `https://blitzwalletapp.com/pay#${invoice}`,
  });
});

test('inline: failures stay private and other chats see only a short notice', async () => {
  const h = createHarness();
  await h.connect(ALICE);
  h.wallet.setOnline(false);
  await chooseInline(h, ALICE, '5000');
  assert.equal(lastInlineEdit(h).text, 'Couldn’t create the invoice.');
  const dm = h.tg.calls.filter(c => c.method === 'sendMessage').at(-1).params;
  assert.equal(dm.chat_id, ALICE);
  assert.match(dm.text, /didn’t respond/);

  await chooseInline(h, ALICE, 'not an amount');
  assert.match(lastInlineEdit(h).text, /Couldn’t create an invoice/);
});

test('inline: a user only ever uses their own wallet; allowlist applies', async () => {
  const h = createHarness();
  await h.connect(ALICE);
  await chooseInline(h, BOB, '5000');
  assert.equal(
    h.wallet.requests.filter(r => r.method === 'make_invoice').length,
    0,
  );
  assert.equal(lastInlineEdit(h).text, 'Couldn’t create the invoice.');

  const p = createHarness({ config: { allowedUsers: new Set([ALICE]) } });
  await inlineQuery(p, BOB, '5000');
  assert.deepEqual(lastInlineAnswer(p).results, []);
});

test('inline: button presses on posted invoices are ignored safely', async () => {
  const h = createHarness();
  await h.bot.handleUpdate({
    update_id: 6000,
    callback_query: {
      id: 'c1',
      from: { id: BOB },
      data: 'nop:0',
      inline_message_id: 'imid-1',
    },
  });
  assert.deepEqual(
    h.tg.calls.map(c => c.method),
    ['answerCallbackQuery'],
  );
});

// ------------------------------------------------- paying invoices posted in chats

// One fake wallet that can both create and pay invoices and look them up.
function chatWallet() {
  const w = createFakeWallet();
  const byHash = new Map(); // payment_hash -> { preimage, paid }
  w.handlers.make_invoice = ({ amount, description, expiry }) => {
    const { preimage, paymentHash } = newPreimage();
    byHash.set(paymentHash, { preimage, paid: false });
    return {
      result: {
        invoice: makeInvoice({
          sats: amount / 1000,
          paymentHash,
          expiry,
          description,
        }),
      },
    };
  };
  w.handlers.pay_invoice = ({ invoice }) => {
    const rec = byHash.get(decodeInvoice(invoice).paymentHash);
    rec.paid = true;
    return { result: { preimage: rec.preimage } };
  };
  w.handlers.lookup_invoice = ({ payment_hash }) => {
    const rec = byHash.get(payment_hash);
    return rec
      ? {
          result: {
            type: 'incoming',
            state: rec.paid ? 'settled' : 'pending',
            preimage: rec.paid ? rec.preimage : '',
          },
        }
      : { error: { code: 'NOT_FOUND', message: '' } };
  };
  return w;
}
const postedPayButton = h =>
  h.tg.calls
    .filter(c => c.params.inline_message_id && c.params.reply_markup)
    .at(-1)
    ?.params.reply_markup.inline_keyboard.flat()
    .find(b => b.callback_data?.startsWith('ip:'))?.callback_data;
const pressInline = (h, userId, data) =>
  h.bot.handleUpdate({
    update_id: 7000,
    callback_query: {
      id: `cb${userId}`,
      from: { id: userId },
      data,
      inline_message_id: 'imid-1',
    },
  });

test('chat pay: Bob pays Alice’s posted invoice via the private chat; message and Alice are updated', async () => {
  const h = createHarness({ wallet: chatWallet() });
  await h.connect(ALICE);
  await h.connect(BOB);
  await chooseInline(h, ALICE, '5000 pizza');
  const data = postedPayButton(h);
  assert.match(data, /^ip:[A-Za-z0-9_-]{22}$/);
  const id = data.slice(3);

  // The button only opens Bob's private chat with the bot.
  await pressInline(h, BOB, data);
  const answer = h.tg.calls
    .filter(c => c.method === 'answerCallbackQuery')
    .at(-1).params;
  assert.equal(answer.url, `https://t.me/BlitzTestBot?start=pay_${id}`);
  assert.equal(
    h.wallet.requests.filter(r => r.method === 'pay_invoice').length,
    0,
  );

  // There, the normal Confirm + PIN flow runs.
  await h.say(BOB, `/start pay_${id}`);
  assert.match(
    h.tg.lastText(),
    /You’re about to pay[\s\S]*5,000 sats[\s\S]*pizza/,
  );
  assert.equal(h.tg.last().chat_id, BOB);
  await h.pressButton(BOB, 'pc:');
  await h.enterPin(BOB, PIN);
  await h.settle();

  assert.equal(
    h.wallet.requests.filter(r => r.method === 'pay_invoice').length,
    1,
  );
  const sent = h.tg.calls
    .filter(c => c.method === 'sendMessage')
    .map(c => [c.params.chat_id, c.params.text]);
  assert.ok(
    sent.some(
      ([chat, text]) => chat === BOB && /✅ Paid <b>5,000 sats/.test(text),
    ),
  );
  assert.ok(
    sent.some(
      ([chat, text]) =>
        chat === ALICE && /💰 Received <b>5,000 sats/.test(text),
    ),
    'Alice told right away',
  );
  assert.match(lastInlineEdit(h).text, /✅ <b>5,000 sats<\/b> paid/);
  assert.equal(
    h.store.getPostedInvoice(id),
    undefined,
    'invoice text dropped once paid',
  );

  // The button is dead afterwards.
  await pressInline(h, BOB, data);
  assert.match(
    h.tg.calls.filter(c => c.method === 'answerCallbackQuery').at(-1).params
      .text,
    /already paid/,
  );
});

test('chat pay: own invoice, unknown ids, private-only bots and unconnected payers', async () => {
  const h = createHarness({ wallet: chatWallet() });
  await h.connect(ALICE);
  await chooseInline(h, ALICE, '1000');
  const data = postedPayButton(h);
  const lastAnswer = () =>
    h.tg.calls.filter(c => c.method === 'answerCallbackQuery').at(-1).params;

  await pressInline(h, ALICE, data);
  assert.equal(lastAnswer().text, 'This is your own invoice.');
  await pressInline(h, BOB, 'ip:doesnotexist');
  assert.match(lastAnswer().text, /already paid or has expired/);

  await h.say(BOB, `/start pay_${data.slice(3)}`);
  assert.match(h.tg.lastText(), /Connect your wallet first/);

  const p = createHarness({
    wallet: chatWallet(),
    config: { allowedUsers: new Set([ALICE]) },
  });
  await p.connect(ALICE);
  await chooseInline(p, ALICE, '1000');
  await pressInline(p, BOB, postedPayButton(p));
  assert.equal(
    p.tg.calls.filter(c => c.method === 'answerCallbackQuery').at(-1).params
      .text,
    'This bot is private.',
  );
});

test('chat pay: an expired posted invoice is marked expired and can no longer be paid', async () => {
  const h = createHarness({ wallet: chatWallet() });
  await h.connect(ALICE);
  await chooseInline(h, ALICE, '1000');
  const id = postedPayButton(h).slice(3);
  h.clock.now += 3600_000 + 61_000;
  await h.bot.runMaintenance();
  assert.match(lastInlineEdit(h).text, /expired unpaid/);
  await h.connect(BOB);
  await h.say(BOB, `/start pay_${id}`);
  assert.match(h.tg.lastText(), /already paid or has expired/);
});
