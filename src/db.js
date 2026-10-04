import { mkdirSync, chmodSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

// Append-only. Each entry runs once, tracked by PRAGMA user_version.
const MIGRATIONS = [
  `CREATE TABLE wallets (
     user_id INTEGER PRIMARY KEY,
     wallet_pubkey TEXT NOT NULL,
     relays TEXT NOT NULL,
     secret_enc TEXT NOT NULL,
     encryption TEXT NOT NULL,
     methods TEXT NOT NULL,
     pin_hash TEXT,
     pin_failures INTEGER NOT NULL DEFAULT 0,
     pin_locked_until INTEGER NOT NULL DEFAULT 0,
     created_at INTEGER NOT NULL
   );
   CREATE TABLE payments (
     id TEXT PRIMARY KEY,
     user_id INTEGER NOT NULL,
     payment_hash TEXT NOT NULL,
     invoice TEXT,
     amount_msat INTEGER NOT NULL,
     status TEXT NOT NULL,
     request_id TEXT,
     request_expires_at INTEGER,
     fee_msat INTEGER,
     checks INTEGER NOT NULL DEFAULT 0,
     next_check_at INTEGER,
     confirm_expires_at INTEGER NOT NULL,
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL
   );
   CREATE INDEX payments_user ON payments(user_id, status);
   CREATE INDEX payments_due ON payments(status, next_check_at);
   CREATE TABLE invoices (
     id TEXT PRIMARY KEY,
     user_id INTEGER NOT NULL,
     payment_hash TEXT NOT NULL,
     amount_msat INTEGER NOT NULL,
     status TEXT NOT NULL,
     expires_at INTEGER NOT NULL,
     checks INTEGER NOT NULL DEFAULT 0,
     next_check_at INTEGER,
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL
   );
   CREATE INDEX invoices_user ON invoices(user_id, status);
   CREATE INDEX invoices_due ON invoices(status, next_check_at);`,
  // Invoices posted in chats via inline mode keep their BOLT11 text (so others
  // can pay them from the posted message) and the message id (to mark them
  // paid). The text is cleared once the invoice is no longer open.
  `ALTER TABLE invoices ADD COLUMN invoice TEXT;
   ALTER TABLE invoices ADD COLUMN inline_message_id TEXT;
   CREATE INDEX invoices_hash ON invoices(payment_hash, status);`,
];

export const IN_FLIGHT = ['submitting', 'unknown'];
export const TERMINAL_PAYMENT = ['paid', 'failed', 'cancelled'];

export function openDb(path) {
  if (path !== ':memory:') {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  }
  const isNew = path === ':memory:' || !existsSync(path);
  const db = new DatabaseSync(path);
  if (path !== ':memory:' && isNew) chmodSync(path, 0o600);
  db.exec(
    'PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA secure_delete = ON;',
  );

  const version = db.prepare('PRAGMA user_version').get().user_version;
  for (let v = version; v < MIGRATIONS.length; v++) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[v]);
      db.exec(`PRAGMA user_version = ${v + 1}`);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }
  return createStore(db);
}

function createStore(db) {
  const q = sql => db.prepare(sql);
  const tx = fn => {
    db.exec('BEGIN IMMEDIATE');
    try {
      const out = fn();
      db.exec('COMMIT');
      return out;
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  };

  return {
    close: () => db.close(),

    // --- wallets -----------------------------------------------------------
    getWallet: userId =>
      q('SELECT * FROM wallets WHERE user_id = ?').get(userId),
    // Replacing a connection also resets the PIN: the PIN belongs to the
    // connection, and reconnecting proves access to the Blitz app.
    upsertWallet: w =>
      q(
        `INSERT INTO wallets (user_id, wallet_pubkey, relays, secret_enc, encryption, methods, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET wallet_pubkey = excluded.wallet_pubkey,
           relays = excluded.relays, secret_enc = excluded.secret_enc, encryption = excluded.encryption,
           methods = excluded.methods, created_at = excluded.created_at,
           pin_hash = NULL, pin_failures = 0, pin_locked_until = 0`,
      ).run(
        w.userId,
        w.walletPubkey,
        JSON.stringify(w.relays),
        w.secretEnc,
        w.encryption,
        w.methods.join(' '),
        w.now,
      ),
    setPin: (userId, pinHash) =>
      q(
        'UPDATE wallets SET pin_hash = ?, pin_failures = 0, pin_locked_until = 0 WHERE user_id = ?',
      ).run(pinHash, userId),
    recordPinFailure(userId, now, maxFailures, lockMs) {
      return tx(() => {
        q(
          'UPDATE wallets SET pin_failures = pin_failures + 1 WHERE user_id = ?',
        ).run(userId);
        const { pin_failures } = q(
          'SELECT pin_failures FROM wallets WHERE user_id = ?',
        ).get(userId);
        if (pin_failures < maxFailures)
          return { locked: false, remaining: maxFailures - pin_failures };
        q(
          'UPDATE wallets SET pin_failures = 0, pin_locked_until = ? WHERE user_id = ?',
        ).run(now + lockMs, userId);
        return { locked: true, remaining: 0 };
      });
    },
    resetPinFailures: userId =>
      q('UPDATE wallets SET pin_failures = 0 WHERE user_id = ?').run(userId),
    walletsNotUnderKey: keyId =>
      q(
        `SELECT user_id, wallet_pubkey, secret_enc FROM wallets WHERE substr(secret_enc, 1, ?) != ?`,
      ).all(`v1.${keyId}.`.length, `v1.${keyId}.`),
    updateSecret: (userId, secretEnc) =>
      q('UPDATE wallets SET secret_enc = ? WHERE user_id = ?').run(
        secretEnc,
        userId,
      ),
    deleteUser: userId =>
      tx(() => {
        q('DELETE FROM payments WHERE user_id = ?').run(userId);
        q('DELETE FROM invoices WHERE user_id = ?').run(userId);
        q('DELETE FROM wallets WHERE user_id = ?').run(userId);
      }),

    // --- payments ----------------------------------------------------------
    createPayment: p =>
      q(
        `INSERT INTO payments (id, user_id, payment_hash, invoice, amount_msat, status, confirm_expires_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'awaiting_confirmation', ?, ?, ?)`,
      ).run(
        p.id,
        p.userId,
        p.paymentHash,
        p.invoice,
        p.amountMsat,
        p.confirmExpiresAt,
        p.now,
        p.now,
      ),
    getPayment: (id, userId) =>
      q('SELECT * FROM payments WHERE id = ? AND user_id = ?').get(id, userId),
    // Any attempt for this hash that is not definitively over blocks a new one.
    blockingPaymentForHash: (userId, paymentHash) =>
      q(
        `SELECT * FROM payments WHERE user_id = ? AND payment_hash = ?
           AND status IN ('submitting', 'unknown', 'paid') LIMIT 1`,
      ).get(userId, paymentHash),
    // THE double-payment guard. One synchronous statement: only one caller can
    // move a confirmation to 'submitting', and only if the user has no other
    // in-flight payment and this hash was not already sent or paid.
    claimForSubmit(id, userId, now) {
      const result = q(
        `UPDATE payments SET status = 'submitting', updated_at = ?
         WHERE id = ? AND user_id = ? AND status = 'awaiting_confirmation' AND confirm_expires_at > ?
           AND NOT EXISTS (SELECT 1 FROM payments o WHERE o.user_id = ? AND o.status IN ('submitting', 'unknown'))
           AND NOT EXISTS (SELECT 1 FROM payments o WHERE o.user_id = ? AND o.id != ?
                           AND o.payment_hash = payments.payment_hash AND o.status = 'paid')`,
      ).run(now, id, userId, now, userId, userId, id);
      return result.changes === 1;
    },
    setPaymentRequest: (id, requestId, requestExpiresAt, now) =>
      q(
        'UPDATE payments SET request_id = ?, request_expires_at = ?, updated_at = ? WHERE id = ?',
      ).run(requestId, requestExpiresAt, now, id),
    // Terminal states drop the invoice string (not needed, minimizes retention).
    // Never moves a payment out of a terminal state.
    updatePayment(
      id,
      { status, feeMsat = null, checks, nextCheckAt = null, now },
    ) {
      const terminal = TERMINAL_PAYMENT.includes(status);
      return (
        q(
          `UPDATE payments SET status = ?, fee_msat = COALESCE(?, fee_msat), checks = COALESCE(?, checks),
           next_check_at = ?, invoice = CASE WHEN ? THEN NULL ELSE invoice END, updated_at = ?
         WHERE id = ? AND status NOT IN ('paid', 'failed', 'cancelled')`,
        ).run(
          status,
          feeMsat,
          checks ?? null,
          nextCheckAt,
          terminal ? 1 : 0,
          now,
          id,
        ).changes === 1
      );
    },
    // One pending confirmation per user: a new one supersedes older ones,
    // which also bounds how many rows a flood of pasted invoices can create.
    cancelAwaiting: (userId, now) =>
      q(
        `UPDATE payments SET status = 'cancelled', invoice = NULL, updated_at = ?
         WHERE user_id = ? AND status = 'awaiting_confirmation'`,
      ).run(now, userId).changes,
    cancelPayment: (id, userId, now) =>
      q(
        `UPDATE payments SET status = 'cancelled', invoice = NULL, updated_at = ?
         WHERE id = ? AND user_id = ? AND status = 'awaiting_confirmation'`,
      ).run(now, id, userId).changes === 1,
    expireConfirmations: now =>
      q(
        `UPDATE payments SET status = 'cancelled', invoice = NULL, updated_at = ?
         WHERE status = 'awaiting_confirmation' AND confirm_expires_at <= ?`,
      ).run(now, now).changes,
    // After a crash we cannot know whether a 'submitting' request was published.
    recoverSubmitting: now =>
      q(
        `UPDATE payments SET status = 'unknown', next_check_at = ?, updated_at = ? WHERE status = 'submitting'`,
      ).run(now, now).changes,
    duePayments: (now, limit = 50) =>
      q(
        `SELECT * FROM payments WHERE status = 'unknown' AND next_check_at <= ? ORDER BY next_check_at LIMIT ?`,
      ).all(now, limit),
    recentPayments: (userId, limit = 5) =>
      q(
        `SELECT * FROM payments WHERE user_id = ? AND status != 'awaiting_confirmation'
         ORDER BY created_at DESC LIMIT ?`,
      ).all(userId, limit),

    // --- invoices ----------------------------------------------------------
    createInvoice: i =>
      q(
        `INSERT INTO invoices (id, user_id, payment_hash, amount_msat, status, expires_at, next_check_at,
           invoice, inline_message_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)`,
      ).run(
        i.id,
        i.userId,
        i.paymentHash,
        i.amountMsat,
        i.expiresAt,
        i.nextCheckAt,
        i.invoice ?? null,
        i.inlineMessageId ?? null,
        i.now,
        i.now,
      ),
    // Not scoped to a user: anyone in the chat may pay a posted invoice. Only
    // open invoices that were posted (have their text stored) are returned.
    getPostedInvoice: id =>
      q(
        `SELECT * FROM invoices WHERE id = ? AND invoice IS NOT NULL AND status = 'open'`,
      ).get(id),
    openInvoiceByHash: paymentHash =>
      q(
        `SELECT * FROM invoices WHERE payment_hash = ? AND status = 'open' LIMIT 1`,
      ).get(paymentHash),
    getInvoice: (id, userId) =>
      q('SELECT * FROM invoices WHERE id = ? AND user_id = ?').get(id, userId),
    openInvoiceCount: userId =>
      q(
        `SELECT COUNT(*) AS n FROM invoices WHERE user_id = ? AND status = 'open'`,
      ).get(userId).n,
    updateInvoice: (id, { status, checks, nextCheckAt, now }) =>
      q(
        `UPDATE invoices SET status = ?, checks = ?, next_check_at = ?, updated_at = ?,
           invoice = CASE WHEN ? = 'open' THEN invoice ELSE NULL END
         WHERE id = ? AND status = 'open'`,
      ).run(status, checks, nextCheckAt, now, status, id).changes === 1,
    dueInvoices: (now, limit = 50) =>
      q(
        `SELECT * FROM invoices WHERE status = 'open' AND next_check_at <= ? ORDER BY next_check_at LIMIT ?`,
      ).all(now, limit),
    inFlightPaymentCount: userId =>
      q(
        `SELECT COUNT(*) AS n FROM payments WHERE user_id = ? AND status IN ('submitting', 'unknown')`,
      ).get(userId).n,
    // A replaced connection points at another wallet; its invoices can no
    // longer be looked up, so stop tracking them.
    closeOpenInvoices: (userId, now) =>
      q(
        `UPDATE invoices SET status = 'untracked', next_check_at = NULL, invoice = NULL, updated_at = ? WHERE user_id = ? AND status = 'open'`,
      ).run(now, userId),
    recentInvoices: (userId, limit = 5) =>
      q(
        'SELECT * FROM invoices WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
      ).all(userId, limit),

    // --- retention ---------------------------------------------------------
    purge: (now, retentionMs) => {
      const cutoff = now - retentionMs;
      return (
        q(
          `DELETE FROM payments WHERE status IN ('paid', 'failed', 'cancelled') AND updated_at < ?`,
        ).run(cutoff).changes +
        q(`DELETE FROM invoices WHERE status != 'open' AND updated_at < ?`).run(
          cutoff,
        ).changes
      );
    },
  };
}
