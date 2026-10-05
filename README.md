# Blitz Wallet Telegram Bot

A Telegram bot that lets Blitz Wallet users check their balance, receive,
send, view transactions and track payments **through their own Blitz Wallet**
using Nostr Wallet Connect (NWC).

> **This bot is not a wallet.** It never holds funds, seeds or Lightning keys.
> It holds one revocable, budget-limited NWC connection per user and asks the
> user's Blitz Wallet (on their phone) to act. Blitz enforces permissions and
> spending budgets; the bot cannot exceed them. NWC in Blitz uses a separate
> "Wallet Connect" sub-account, so the main Blitz balance is never reachable.

Full architecture, threat model and every security decision:
[docs/DESIGN.md](docs/DESIGN.md).

## Architecture in one picture

```
Telegram user ⇄ Telegram ⇄ (long polling) bot ⇄ Nostr relay ⇄ Blitz Wallet (phone)
                                  │                 NIP-44 encrypted, signed,
                              SQLite (secrets       expiring NWC requests
                              AES-256-GCM encrypted)
```

| File              | Responsibility                                                                              |
| ----------------- | ------------------------------------------------------------------------------------------- |
| `src/index.js`    | Startup, key rotation, crash recovery, polling, graceful shutdown                           |
| `src/config.js`   | Validated configuration (fails fast)                                                        |
| `src/telegram.js` | Bot API client + long polling (no inbound port)                                             |
| `src/bot.js`      | Commands, confirmation + PIN, payment state machine, reconciler, rate limits                |
| `src/nwc.js`      | Connection-string parsing, relay allowlist, NIP-44/04, request signing, response validation |
| `src/invoice.js`  | BOLT11 validation and preimage verification                                                 |
| `src/db.js`       | SQLite schema, migrations and all queries (parameterized)                                   |
| `src/crypto.js`   | AES-256-GCM keyring, scrypt PIN hashing                                                     |
| `src/log.js`      | JSON logger with secret redaction and pseudonymous user ids                                 |

## Setup

Requirements: Node.js ≥ 22.13 (uses built-in `node:sqlite` and `node:test`).
Runtime dependencies: `nostr-tools` and `light-bolt11-decoder` (the same
libraries Blitz Wallet uses).

```bash
npm ci
```

1. Create a bot with [@BotFather](https:///t.me/BotFather). Then in BotFather:
   **Bot Settings → Allow Groups → Turn off** (the bot also leaves groups by
   itself).
2. Generate an encryption key:
   ```bash
   echo "k1:$(openssl rand -base64 32)"
   ```
3. Provide configuration (see below), then start:
   ```bash
   npm start
   ```

For local development: `cp env.example .env`, fill it in, and run
`node --env-file=.env --disable-warning=ExperimentalWarning src/index.js`.

## Configuration

| Variable                                         | Required | Meaning                                                                                                                       |
| ------------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_BOT_TOKEN_FILE` | yes      | Bot token. Prefer the `_FILE` form.                                                                                           |
| `ENCRYPTION_KEYS` / `ENCRYPTION_KEYS_FILE`       | yes      | `id:base64key[,id:base64key…]`. First key encrypts; all decrypt. Prefer `_FILE`.                                              |
| `DATABASE_PATH`                                  | no       | SQLite file, default `./data/bot.db` (created `0600`, dir `0700`).                                                            |
| `ALLOWED_RELAYS`                                 | no       | Comma-separated `wss://` relays connections may use. Default `wss://relay.getalbypro.com/blitz` (Blitz's relay).              |
| `ALLOWED_TELEGRAM_USER_IDS`                      | no       | Restrict the bot to these numeric Telegram ids (private deployments).                                                         |
| `MAX_PAYMENT_SATS`                               | no       | Bot-side cap per payment, default 1,000,000. The wallet budget is the real limit.                                             |
| `CONNECT_DAILY_BUDGET_SATS`                      | no       | Daily spending limit the bot asks Blitz for when pairing, default 100,000 (`0` = ask for none). Users can change it in Blitz. |
| `LOG_LEVEL`                                      | no       | `debug`/`info`/`warn`/`error`, default `info`.                                                                                |

Invalid configuration stops the bot at startup with a message that never
contains secret values.

## Database

SQLite (`node:sqlite`), WAL mode, `secure_delete` on. Migrations run
automatically at startup (`PRAGMA user_version`). Tables: `wallets` (one
connection per Telegram user; secret encrypted), `payments`, `invoices`.
Terminal payments/invoices are deleted after 7 days; `/disconnect` deletes a
user's rows immediately. Backups contain only ciphertext for secrets — **never
back up the encryption key alongside the database.**

## Using the bot (users)

1. Send `/connect`. Pick your language, then tap **Connect in Blitz** on the phone with Blitz (or scan
   the `nostr+walletauth://` text with Blitz on another device). Blitz shows
   what the bot asks for; "Send payments" is off unless you turn it on, and
   sending is capped by the daily limit shown. Approve.
2. The bot connects. Nothing secret is ever copied or sent through Telegram:
   the bot generated its own key and Blitz only learned the public half
   (NWC-08). If you allowed sending, set a 6-digit payment PIN on the inline
   keypad (it never appears in chat history).
3. Commands: `/balance`, `/receive 21000 memo`, `/send` (or paste an invoice),
   `/transactions`, `/status`, `/disconnect`, `/help`, `/language`.

**Request money in any chat (inline mode):** type `@YourBot 5000 pizza` in
any chat and tap the result. The bot creates the invoice in your Blitz wallet
and posts a request (amount, memo, expiry; the invoice text itself is hidden)
with three buttons: **⚡ Open wallet** (opens any Lightning wallet via
`blitzwalletapp.com/pay`), **📋 Copy invoice**, and **Pay with @bot**, which
opens the payer's private chat with the bot, where they confirm and enter their
PIN as for any payment. When it's paid, the
posted message changes to "✅ paid" and you get a private message. Needs
BotFather `/setinline` (placeholder text) **and** `/setinlinefeedback` →
Enabled, otherwise Telegram never tells the bot which result was picked.

Older Blitz version without the pairing screen? `/connect_manual` explains the
old way: create a connection in Blitz → Settings → Wallet Connect and paste the
connection string (the bot deletes that message immediately).

Payments always show amount, the recipient's memo and expiry, and require
**Confirm** + PIN. Forgot the PIN? `/disconnect` and connect again.

## Security model (summary)

- **What a leaked NWC credential can do:** whatever that connection was granted
  in Blitz, up to its budget and the Wallet Connect balance, until the user
  deletes the connection in Blitz. It cannot touch the main Blitz wallet.
- **Database stolen without the key:** no usable credentials.
- **Database + key, or a live server compromise:** every connected user's
  connection can be used up to their budget. This is the inherent residual risk
  of a server-side NWC client; it is bounded by Blitz budgets. See incident
  response below.
- **Telegram account takeover:** can read balance/history and create invoices;
  paying additionally requires the PIN (10 wrong tries, then locks of 1 min, 5 min, 15 min, 30 min, 1 h, 5 h and 24 h, then sending is off until re-pairing).
- **Relay:** sees metadata only; cannot read, forge or successfully replay.
- Secrets are never logged, never echoed to users, never in URLs or command-line
  arguments; logs use HMAC pseudonyms instead of Telegram ids.

## Payment safety and failure states

- A payment is sent **exactly once** per confirmation; there is no retry path.
- Paid = the wallet returned a preimage whose SHA-256 equals the invoice's
  payment hash (or `lookup_invoice` reports `settled`).
- Failed = a NIP-47 error that guarantees nothing was sent (`QUOTA_EXCEEDED`,
  `INSUFFICIENT_BALANCE`, `PAYMENT_FAILED`, …) or, after the request's
  `expiration` plus 2 minutes, the wallet has no record of it.
- **Unknown** = anything else (timeout, `INTERNAL`, crash). Users are told not
  to pay again; the bot reconciles with `lookup_invoice` (1 min → 6 h backoff,
  up to 3 days) and messages the user when it resolves.
- Same invoice cannot be paid twice; one in-flight payment per user; Blitz also
  dedupes by payment hash.

## Deployment

The bot is a single long-running Node process with no inbound ports (long
polling). Run exactly **one instance per bot token** (Telegram allows one
`getUpdates` consumer; the payment CAS is also per-database).

- Mount secrets as files (`TELEGRAM_BOT_TOKEN_FILE`, `ENCRYPTION_KEYS_FILE`),
  readable only by the bot user. Do not bake them into images or pass them as
  CLI arguments.
- Persist `DATABASE_PATH` on a volume; keep the key on a different secret store.
- Send `SIGTERM` to stop: polling stops, in-flight work gets up to 10 s, then
  relays and DB are closed. Payments interrupted mid-flight resume as
  "unknown" on next start.
- Egress needed: `api.telegram.org:443` and the allowed relay(s), directly.
  Node 22's `fetch` ignores `HTTPS_PROXY` by default, so a host that can only
  reach the internet through a proxy needs a Node version/flag with proxy
  support (e.g. `NODE_USE_ENV_PROXY=1` where available).

## Testing

```bash
npm test
```

69 tests (`node:test`) run against an in-memory database, a fake Telegram API,
and a fake relay + Blitz-like wallet that uses real nostr signing and NIP-44
encryption. Covered: inline mode (no wallet calls while typing, invoice on
selection, private errors, isolation, paying posted invoices), NWC-08 pairing (link contents, approval, forged/wrong-state
events, relay allowlist, replacement, expiry), authorization and allowlist, groups, user isolation and
forged callbacks, connection (valid/invalid/revoked/unauthorized), disconnect
and reconnect, the full payment state machine (paid, failed, unknown,
reconciliation, NOT_FOUND grace, restart recovery, duplicate and concurrent
confirmations, PIN lockout), invoices (creation, paid, expired, amount
mismatch, caps), balance, transactions pagination, rate limiting, relay
allowlist/SSRF, response forgery, encryption negotiation, key rotation, and
that secrets/PINs never appear in logs or Telegram output.

Not covered automatically: a live run against a real Blitz Wallet and
Telegram (needs a bot token and a funded test wallet) — do this before
production.

## Operational monitoring

Logs are JSON lines on stdout. Useful signals:

- `payment outcome` with `status: unknown` — rising counts mean relay or
  wallet delivery problems.
- `wrong payment pin` with `locked: true` — possible account takeover attempts.
- `telegram poll failed` — Telegram/API connectivity.
- `cannot decrypt wallet secret` — key misconfiguration (missing old key during
  rotation).
- `maintenance failed`, `unhandled rejection`, `uncaught exception` — bugs.

Key rotation: prepend a new key (`k2:…,k1:…`), restart (rows are re-encrypted
at startup and the count is logged as `rotated`), then remove `k1` and restart.

## Incident response

**Encryption key and/or database leaked, or server compromised:**

1. Stop the bot. Revoke the bot token in BotFather (`/revoke`).
2. Tell users to delete the Telegram connection in **Blitz → Settings → Wallet
   Connect** immediately. This is the only real revocation; until then a stolen
   secret works up to the connection's budget.
3. Rotate the encryption key, rebuild the host, deploy with a fresh database
   (old secrets are useless once users delete the connections).
4. Users reconnect with new connection strings.

**Bot token leaked only:** revoke it in BotFather, deploy the new token. Warn
users who connected during the exposure window to rotate their connection.

**Database leaked only (key safe):** secrets remain encrypted; still rotate the
key as a precaution. Leaked metadata: Telegram ids, wallet pubkeys, amounts and
payment hashes from the last 7 days.

**A user's Telegram account compromised:** the user deletes the connection in
Blitz and terminates other Telegram sessions; then reconnects with a new
connection.
