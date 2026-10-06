# Blitz Telegram Bot — Design and Security Decisions

Status: implemented (v0.1). This document is the source of truth for the
architecture and security decisions. Operational docs live in `README.md`.

**The bot is a remote control, not a wallet.** It holds no seed, no Lightning
keys and no funds. It holds one revocable NWC credential per user and uses it
to ask the user's Blitz Wallet to do things. Every payment is executed — and
every spending limit enforced — by Blitz on the user's phone.

---

## 1. What exists today (findings that drive the design)

Facts established from the BlitzWallet repository (`app/functions/nwc/*`,
`android/.../nwc/NwcHandler.kt`, `ios/NotificationService/NwcHandler.swift`) and
the current NIP-47 / NWC extension specs (NWC-05, 08, 09):

| Finding                                                                                                                                                                                                                                                                                 | Consequence for the bot                                                                                                                                                    |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Blitz NWC runs on a **separate Spark sub-wallet with its own seed** ("Wallet Connect account"). The main wallet's keys are never used for NWC.                                                                                                                                          | The worst case for any NWC credential leak is bounded by the Wallet Connect account balance (and the budget). The main Blitz balance is unreachable through NWC.           |
| Per-connection **permissions** (`make_invoice`, `pay_invoice`, `get_balance`, `list_transactions`, `lookup_invoice`) and a **budget** (amount + daily/weekly/monthly/yearly/never) are enforced **by the wallet**, atomically (`reserveSpend` ledger shared by JS and native handlers). | Wallet-side limits are the only limits that survive a bot compromise. The bot asks users to create a dedicated connection with a budget.                                   |
| All connections share the one Wallet Connect sub-wallet balance and its history. `list_transactions` returns sub-wallet history, not per-connection history.                                                                                                                            | Users must understand "balance" = Wallet Connect account. Documented in UX.                                                                                                |
| Blitz is not an always-on wallet service: requests reach the phone through a push relay (`wss://relay.getalbypro.com/blitz` → Blitz backend → push). Responses take seconds and may never arrive if the phone is offline or notifications are off.                                      | Timeouts are normal. "No response" must never be treated as "failed" for payments.                                                                                         |
| Blitz rejects request events older/newer than 300 s and **honors the `expiration` tag** (JS, Android, iOS). A handed-off `pay_invoice` without `expiration` older than 60 s is refused.                                                                                                 | Every bot request carries `expiration`. After `expiration` + grace, a payment request that left no trace in the wallet can be concluded "not sent".                        |
| Blitz **dedupes request event ids** (event ledger) and makes `pay_invoice` **idempotent by payment_hash**: a completed hash returns its preimage, an in-flight hash returns "Payment already in progress", only a `failed` hash may be re-sent.                                         | Re-sending the same invoice cannot double-pay in Blitz. The bot still never auto-retries (defense in depth, and other wallets may differ).                                 |
| Blitz `pay_invoice` can return a **`result` with an empty `preimage`** when the payment is still pending or even failed. Errors use `INTERNAL` both for "never left" and "status unknown".                                                                                              | A response is "paid" **only** if `sha256(preimage) == payment_hash`. Everything else is reconciled with `lookup_invoice`. `INTERNAL`/`OTHER` mean "unknown", not "failed". |
| Every handled request fires a user-visible push notification on the phone (including `lookup_invoice`).                                                                                                                                                                                 | Status polling must be sparse (backoff), or the user's phone is spammed.                                                                                                   |
| Blitz only supports amount-bearing BOLT11 invoices for `pay_invoice` (no amountless). Its `list_transactions` omits the optional `state` field.                                                                                                                                         | Bot rejects amountless invoices up front; tolerates missing `state`.                                                                                                       |
| Blitz only emits NWC-02 `payment_sent` notifications, not `payment_received`.                                                                                                                                                                                                           | Incoming-invoice settlement is detected by (sparse) `lookup_invoice`, plus a manual "Check" button.                                                                        |
| Connection strings are generated by Blitz (`nostr+walletconnect://<walletPubkey>?relay=…&secret=…`). Blitz does **not** implement NWC-08 (client-generated keys).                                                                                                                       | See §4: the paste flow is the only flow Blitz supports today; mitigated, with NWC-08 as the recommended Blitz follow-up.                                                   |
| NIP-47 core no longer defines `list_transactions`; it is NWC-05 (Blitz implements it). Payment reconciliation is `lookup_invoice` (core) / `lookup_payment` (NWC-09, not in Blitz).                                                                                                     | Bot uses `lookup_invoice` by `payment_hash`.                                                                                                                               |

---

## 2. Security boundary (who controls what)

| Party                           | Controls                                                                                                                                                                          | Cannot do                                                                                                                                                     |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Blitz Wallet (phone)**        | Keys and funds of the Wallet Connect sub-wallet; which client pubkeys are authorized; per-connection permissions and budget; payment idempotency; revocation (delete connection). | —                                                                                                                                                             |
| **Telegram bot (this service)** | The NWC client secret (encrypted at rest); which Telegram user may use which connection; confirmation + PIN before payments; bot-side per-payment cap; rate limits.               | Spend beyond the wallet budget/balance; touch the main Blitz wallet; pay without the wallet signing off.                                                      |
| **Telegram**                    | Identity of the sender of each update (`from.id`); message delivery and storage (cloud chats, **not** end-to-end encrypted for bots).                                             | Sign NWC requests (does not have the NWC secret unless a user pasted it and Telegram retains it — see §4).                                                    |
| **NWC (protocol)**              | Authenticated (Schnorr-signed), encrypted (NIP-44) request/response envelope bound to a client key; method set is advertised by the wallet.                                       | Enforce anything by itself — enforcement is the wallet's job.                                                                                                 |
| **Nostr relay**                 | Delivery. Sees metadata: kinds, timestamps, wallet/client pubkeys, `e`/`p` tags, payload sizes. Can drop, delay or replay events.                                                 | Read payloads (NIP-44), forge responses (signature + author + `e`/`p` checks), replay successfully (wallet event-id dedupe + 300 s freshness + `expiration`). |

**The precise statement:** an attacker holding a user's NWC secret can, for as
long as the connection exists in Blitz, perform every method that connection was
granted: send payments up to the remaining **budget**, bounded by the
**Wallet Connect sub-wallet balance**; read that sub-wallet's balance and full
history; create invoices that pay into it. They cannot reach the main Blitz
wallet. Only deleting the connection in Blitz revokes the credential —
`/disconnect` in the bot only deletes the bot's copy.

---

## 3. NWC permission model and defense in depth

- **Dedicated connection.** Users create a connection named "Telegram" used only
  by the bot, so it can be revoked independently and its budget sized for
  Telegram use.
- **Minimum permissions.** The bot needs: `get_balance`, `make_invoice`,
  `lookup_invoice`, `list_transactions`, and (only if the user wants to send)
  `pay_invoice`. It reads the granted set from `get_info` at connect time and
  disables features that were not granted. Users who only want to receive can
  omit "Send payments" — then even a full bot compromise cannot spend.
- **Budget.** Blitz enforces it atomically; the bot cannot verify the budget
  (Blitz exposes no `get_budget`), so onboarding instructs users to set one and
  the docs explain why it is the real backstop.
- **Bot-side controls (defense in depth, do not survive bot compromise):**
  explicit confirmation, payment PIN, `MAX_PAYMENT_SATS` per payment,
  one in-flight payment per user, rate limits, request expiration.
- **Revocation.** Deleting the connection in Blitz makes requests go
  unanswered (Blitz drops events from unknown clients silently) or return
  `UNAUTHORIZED` (other wallets). The bot reports this as "wallet not
  responding or connection removed" and never as a payment failure.
- **Wallet offline / relay down:** request times out → read ops show "wallet
  didn't respond"; payments enter `unknown` and are reconciled.
- **Response authentication:** the bot accepts a response only if it is kind
  23195, has a valid signature, is authored by the wallet pubkey from the
  connection string, `p`-tags our client pubkey, `e`-tags our request id,
  decrypts with the negotiated scheme, and has `result_type == method`. Payment
  success additionally requires `sha256(preimage) == payment_hash`. A
  `make_invoice` result must decode as a mainnet BOLT11 invoice for exactly the
  requested amount.

---

## 4. Telegram security model and onboarding (challenging the paste flow)

**Identity.** `from.id` of a private-chat update is Telegram's stable numeric
user id; updates arrive over TLS from Telegram via `getUpdates` authenticated by
the bot token, so they cannot be spoofed by third parties. Usernames are mutable
and never used for authorization. Every wallet row, payment and invoice is keyed
by `from.id`; every callback re-checks that the row belongs to `from.id`.
Callback data is attacker-controllable (custom clients can send any bytes), so
it only carries random, unguessable ids that are re-validated server-side.

**Private chats only.** The bot refuses to operate in groups/channels (wallet
replies, balances and confirmations would leak to other members, and replies or
mentions could cause identity confusion). Operators should also disable "Allow
Groups" in BotFather.

**Chat history is not a secret store.** Bot chats are Telegram cloud chats (no
secret chats for bots). Anything sent is stored on Telegram's servers and on
every logged-in device. `deleteMessage` removes a message for both sides in a
private chat, but deletion cannot be treated as secret destruction (server
retention, backups, notification previews, already-synced devices).

**Options considered for getting the credential into the bot:**

| Option                                                         | Secret ever in Telegram?                                          | Cost                                                                                       | Verdict                                                                                                         |
| -------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| A. Paste connection string in chat                             | Yes (deleted immediately, best-effort)                            | none                                                                                       | Removed: the bot never connects from a pasted string; it only deletes it and warns                              |
| B. One-time HTTPS pairing page                                 | No (clipboard → HTTPS form)                                       | public HTTPS server, TLS/domain, CSRF, link tokens; bot otherwise needs zero inbound ports | Rejected: moves the same pasted secret over another channel at the cost of a new internet-facing attack surface |
| C. Telegram Mini App + client-side encryption                  | Ciphertext only                                                   | static hosting + page-integrity trust                                                      | Rejected for v1: same user paste, extra moving parts                                                            |
| D. **NWC-08 client-initiated pairing** (`nostr+walletauth://`) | **Never** — bot generates the key, only public keys are exchanged | Blitz app support (now implemented)                                                        | **Default `/connect` flow** — see §18                                                                           |

The marginal risk of option A over the unavoidable risk is narrower than it
looks: anyone who controls the user's Telegram account can already drive the
bot. What A adds is (1) the secret could be used _outside_ the bot (bypassing
confirmation/PIN), and (2) Telegram-side retention. Option D removes both, so
it is the only way to connect (the paste flow was removed). A string pasted
anyway is still deleted on sight and flagged. The old paste mitigations:

1. The bot deletes any message containing a connection string **before**
   processing it, in any chat; strings seen in a group are refused and the user
   is told to delete that connection in Blitz.
2. Connection strings are parsed strictly and never echoed, logged or stored
   unencrypted.
3. Users are told to create a **dedicated connection with a budget**, so the
   credential's power is capped by the wallet.
4. Payments require a **PIN entered on an inline keypad**. Button presses are
   callback queries, not messages, so the PIN never appears in chat history —
   a later Telegram account takeover cannot read it from history.
5. Forgotten PIN = `/disconnect` and connect again with a connection string,
   i.e. PIN reset requires access to the Blitz app. A connection without a
   PIN (setup cancelled or expired) cannot send; setting one also needs a
   fresh pairing.
6. Guessable PINs (repeats, sequences, keypad patterns, dates) are rejected.

**Telegram account compromise:** attacker can read balance/history and create
invoices; to pay they also need the PIN (10 wrong tries, then locks of 1 min,
5 min, 15 min, 30 min, 1 h, 5 h and 24 h, then sending is off until
re-pairing; persisted, only a correct PIN resets the count; 17 guesses in
total). They cannot raise the budget. Response: user deletes the connection
in Blitz (instant, total revocation) and terminates Telegram sessions.

**Bot token compromise:** attacker can impersonate the bot and race
`getUpdates` to read incoming messages (including a connection string pasted at
that moment, and PIN keypad callbacks). They cannot read the database or sign
NWC requests. Response: revoke the token in BotFather; affected users rotate
connections.

---

## 5. Secret storage

- Stored secret: only the 32-byte NWC client secret (plus wallet pubkey and
  relay, which are not secret). Never the full connection string.
- **AES-256-GCM** with a random 96-bit IV per encryption; AAD binds the
  ciphertext to `telegram user id + wallet pubkey` so ciphertexts cannot be
  swapped between rows. Format: `v1.<keyId>.<iv>.<ciphertext+tag>`.
- **Key separate from the DB**: supplied via `ENCRYPTION_KEYS` or (preferred)
  `ENCRYPTION_KEYS_FILE` (Docker/K8s secret). Never in the DB, repo, image or
  backups.
- **Rotation**: `ENCRYPTION_KEYS="k2:<b64>,k1:<b64>"` — first key encrypts, all
  keys decrypt; on startup every row not under the primary key is re-encrypted.
  After one successful start, remove the old key.
- **Key lost** → stored connections are unusable; users reconnect. No funds
  are lost (funds never left the wallet).
- **DB stolen, key not** → ciphertexts are useless; attacker learns Telegram
  ids, wallet pubkeys, relay, payment/invoice metadata (amounts, hashes,
  timestamps) for retention window. Not enough to move funds.
- **DB and key stolen** (or live server compromise) → attacker can sign
  requests for **every connected user**: spend up to each user's remaining
  budget and Wallet Connect balance, read their history. This is the
  irreducible residual risk of any server-side NWC client. Bounded by wallet
  budgets; remedied only by users deleting connections in Blitz. Incident
  procedure in README.
- PIN: scrypt (N=2^15, r=8, p=1, 16-byte salt), compared in constant time,
  and the hash is stored AES-GCM-encrypted with the keyring (AAD
  `pin:<user>:<wallet pubkey>`), so a stolen database alone cannot be
  brute-forced offline. It
  is a bot-side gate only; it does not encrypt anything (deriving keys from it
  would block read-only commands and not stop a live-server attacker who can
  capture PINs).
- Logs: structured JSON, no message text, no amounts, pseudonymous user ids
  (HMAC), and a last-line redactor that scrubs connection strings, 64-hex
  secrets, BOLT11 invoices and bot tokens.

---

## 6. Payments (highest risk)

**Validation before showing a confirmation:** strip `lightning:` prefix; decode
BOLT11; require mainnet (`lnbc`), an amount, a payment hash, not expired (with
30 s margin), amount ≤ `MAX_PAYMENT_SATS`, connection has `pay_invoice`, and no
existing non-failed payment for the same payment hash for this user. Signature
and route checks are left to the wallet.

**Confirmation screen:** amount (sats), recipient's memo (clearly labelled as
written by the recipient, truncated, HTML-escaped), expiry, short payment hash,
remaining PIN state. The destination node id is **not** shown: it is not
human-meaningful, cannot be tied to a person, and showing it would give a false
sense of verification.

**Confirmation → PIN → submit** (every payment, no small-payment fast path: one
code path is easier to keep correct, and the wallet budget already caps
convenience risk).

### State machine

```
              cancel / timeout (2 min)
 awaiting_confirmation ───────────────────────────► cancelled
        │ Confirm + correct PIN (atomic CAS; one in-flight per user)
        ▼
   submitting  ── row durably written with request id + expiration BEFORE publish
        │ publish + wait (60 s)
        ├── result, sha256(preimage)==hash ───────────► paid
        ├── definitive error (QUOTA_EXCEEDED, INSUFFICIENT_BALANCE,
        │   RESTRICTED, UNAUTHORIZED, RATE_LIMITED, NOT_IMPLEMENTED,
        │   UNSUPPORTED_ENCRYPTION, PAYMENT_FAILED) ──────► failed
        └── anything else: timeout, INTERNAL/OTHER, result without valid
            preimage, crash, restart ────────────────────► unknown
                                                           │ reconciler: lookup_invoice(payment_hash)
                    settled + valid preimage ─► paid       │ with backoff 1m→6h
                    failed ───────────────────► failed     │
                    pending ──────────────────► unknown (keep checking)
                    NOT_FOUND after expiration+grace ─► failed ("never sent")
                    NOT_FOUND before that / timeout ──► unknown (keep checking)
                    still unknown after 3 days ───► stays unknown; user told to check Blitz
```

- **No automatic retries, ever.** The bot sends `pay_invoice` exactly once per
  confirmed payment row. Recovery only uses `lookup_invoice`.
- **Double payment prevention** (layered): (1) CAS
  `awaiting_confirmation → submitting` in a single synchronous SQLite statement
  — duplicate callbacks/updates lose the race; (2) one in-flight payment per
  user; (3) same payment hash cannot be confirmed again unless the previous
  attempt is definitively `failed`; (4) wallet event-id dedupe; (5) wallet
  payment-hash idempotency; (6) Lightning payment hashes settle once.
- **Crash after publish / Telegram never receives the reply**: the row is
  `submitting`; on restart it is moved to `unknown` and reconciled. The user is
  notified when it resolves.
- **"Unknown" is shown as unknown**: "We couldn't confirm this payment yet. Do
  not pay this invoice again; check Blitz. We'll message you when it resolves."
- A user may retry an invoice only after the previous attempt is `failed`.

---

## 7. Receiving (invoices)

- `/receive <sats> [memo]` → `make_invoice` with `amount` (msat), optional memo
  (≤ 100 chars), `expiry` = 1 h. The result invoice is decoded and must match
  the requested amount; its payment hash is stored (the BOLT11 string is not).
- Max 5 open invoices per user (bounds polling and phone push spam).
- Status: a **Check** button and `/status`; automatic checks at roughly
  1, 3, 10, 30 min and just after expiry (each check is a push to the user's
  phone, so they are deliberately few). Paid → user notified. Expired → closed.
- After restart the schedule simply resumes from `next_check_at` in the DB.
- Isolation: invoice rows are looked up by `(id, telegram user id)`.

## 8. Transaction history

- `list_transactions` (NWC-05), 10 per page, `offset` pagination with
  Prev/Next buttons, max 20 pages (200 tx) back; relays reject large payloads
  and older history belongs in the app.
- Shows date (UTC), direction, amount in sats, fee, state when provided.
- **Memos are not shown**: descriptions may contain personal data and the chat
  is retained by Telegram. Users can see memos in Blitz.
- Nothing is persisted by the bot; history is fetched on demand from the
  user's own connection, so cross-user leakage is impossible by construction.

## 9. Data model (SQLite, `node:sqlite`)

```sql
wallets(          -- one connection per Telegram user
  user_id INTEGER PRIMARY KEY,         -- Telegram from.id
  wallet_pubkey TEXT NOT NULL,
  relays TEXT NOT NULL,                -- JSON array, allowlisted
  secret_enc TEXT NOT NULL,            -- AES-256-GCM, see §5
  encryption TEXT NOT NULL,            -- 'nip44_v2' | 'nip04'
  methods TEXT NOT NULL,               -- granted methods (get_info)
  pin_hash TEXT, pin_failures INTEGER, pin_locked_until INTEGER,
  created_at INTEGER NOT NULL)

payments(
  id TEXT PRIMARY KEY,                 -- 128-bit random, used in callbacks
  user_id, payment_hash, invoice,      -- invoice nulled once terminal
  amount_msat, status, request_id, request_expires_at,
  fee_msat, checks, next_check_at, confirm_expires_at, created_at, updated_at)

invoices(
  id TEXT PRIMARY KEY, user_id, payment_hash, amount_msat,
  status, expires_at, checks, next_check_at, created_at, updated_at)
```

One wallet per Telegram user: the simplest model; replacing a connection
overwrites it (user is reminded to delete the old one in Blitz). Not stored:
seeds, keys, connection strings, balances, history, message contents, memos,
preimages, PIN digits.

**Retention:** terminal payments/invoices are deleted 7 days after their last
update (`invoice` strings are nulled at terminal time). `/disconnect` deletes
the wallet row and all of the user's payments and invoices immediately
(pending ones included — the wallet remains the record of truth).

## 10. Reliability

| Failure                                    | Behavior                                                                                                               |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| Telegram API down                          | Polling backs off and retries; payment state is in the DB, notifications are sent when Telegram returns (best-effort). |
| Relay down / wallet offline / phone asleep | Request times out; reads say so; payments → `unknown` → reconciled.                                                    |
| Connection revoked                         | No response (Blitz) or `UNAUTHORIZED`: user told the connection may have been removed.                                 |
| Invalid / expired invoice                  | Rejected before confirmation; re-checked at Confirm time.                                                              |
| Bot restart / crash                        | `submitting` rows → `unknown`; reconciler resumes; open invoices resume schedule; awaiting confirmations expire.       |
| Database outage                            | Operation fails closed with a generic error; payments never proceed without a durable `submitting` row.                |
| Duplicate update / callback                | `getUpdates` offset dedupes; CAS makes confirm idempotent.                                                             |
| Concurrent payments                        | One in-flight per user enforced inside the CAS.                                                                        |
| Network partition after publish            | `unknown`, never `failed`.                                                                                             |
| Shutdown (SIGTERM)                         | Stop polling, wait ≤ 10 s for handlers, close relays, close DB. In-flight payments resume as `unknown` on next start.  |

## 11. Abuse prevention

- Per-user token buckets: 40 updates burst / 30 per min (keypad taps are
  updates); wallet-touching commands 4 burst / 8 per min (each one wakes the
  user's phone). Global cap of 100 concurrent wallet requests.
- One pending payment confirmation per user (a new one supersedes the old),
  which also bounds rows created by invoice spam.
- PIN lockout (10 wrong tries, then locks of 1 min, 5 min, 15 min, 30 min, 1 h, 5 h and 24 h, then sending is off until re-pairing), persisted.
- One in-flight payment per user; 5 open invoices per user.
- Confirmations expire after 2 minutes; callbacks validated by owner + state.
- Optional `ALLOWED_TELEGRAM_USER_IDS` for private deployments.
- Relay allowlist (`ALLOWED_RELAYS`, default the Blitz relay) — prevents SSRF
  via attacker-chosen `relay=` URLs and limits outbound connections.
- Input caps: message length, memo length, invoice length (≤ 2048).
- Social engineering: confirmation shows "memo is written by the recipient";
  `/help` warns that Blitz never asks for connection strings or PINs.

## 12. Architecture

```
 Telegram user ──(TLS)── Telegram servers ──getUpdates/sendMessage (HTTPS, bot token)──┐
                                                                                       │
                     ┌──────────────────────── Blitz Telegram Bot (one process) ───────┴──┐
                     │ telegram.js  Bot API client + long polling                         │
                     │ bot.js       commands, callbacks, confirmation, PIN, rate limits   │
                     │ payments     state machine + reconciler (in bot.js)                │
                     │ nwc.js       URI parsing, NIP-44/04, request/response validation   │
                     │ db.js        SQLite + migrations    crypto.js  AES-GCM keyring, PIN │
                     │ log.js       redacting JSON logger  config.js  validated config    │
                     └───────────────┬──────────────────────────────────────────────────────┘
                                     │ kind 23194 (signed, NIP-44, expiration) / 23195
                               Nostr relay (allowlisted, wss)
                                     │ Blitz push backend
                               Blitz Wallet (phone): verifies client key, permissions,
                               budget, idempotency; pays from Wallet Connect sub-wallet
```

**Trust boundaries:** (1) Telegram ↔ bot (authenticated by bot token; user
identity = `from.id`); (2) bot ↔ relay (untrusted transport; integrity from
signatures, confidentiality from NIP-44); (3) relay ↔ wallet (wallet verifies
everything); (4) bot process ↔ its DB/key/env (DB alone is not enough; DB + key
= user-wide compromise bounded by budgets).

**Flows**

- _Connect (default, NWC-08)_: `/connect` → bot generates key + `state` →
  "Connect in Blitz" link → user approves in Blitz → Blitz publishes signed
  info event (`p` = bot key, `state`) → bot verifies, encrypts + upserts →
  PIN setup if `pay_invoice` granted. Details in §18.
- _Receive_: `/receive` → `make_invoice` → validate → store hash → show invoice
  - Check button → scheduled `lookup_invoice` → notify on paid.
- _Send_: paste invoice / `/send` → validate → `awaiting_confirmation` →
  Confirm → PIN → CAS → `submitting` → `pay_invoice` once → §6 states.
- _Balance_: `get_balance` → sats.
- _Transactions_: `list_transactions` page → render (no memos).
- _Status_: list user's tracked payments/invoices; Refresh triggers lookups for
  non-terminal ones (rate-limited).
- _Disconnect_: confirm → delete rows → remind to delete connection in Blitz.

## 13. Threat model (concise)

| Asset                   | Attacker                       | Attack                           | Impact                                                | Mitigation                                                                                      | Residual                                                   |
| ----------------------- | ------------------------------ | -------------------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| NWC secret              | DB thief                       | Read DB/backup                   | None without key                                      | AES-GCM, key outside DB                                                                         | Metadata exposure (ids, amounts, hashes ≤ 7 days)          |
| NWC secrets (all users) | Server root / DB+key           | Sign requests                    | Spend ≤ each user's budget & WC balance; read history | Wallet budgets, separate sub-wallet, minimal permissions, key via secret file, incident runbook | **Real; bounded by budgets**                               |
| One user's funds        | Telegram account taker         | Use bot                          | Read balance/history; pay needs PIN                   | PIN on keypad (not in history), lockout, bot cap, wallet budget                                 | 17 PIN guesses total, then sending is off until re-pairing |
| NWC secret              | Telegram (company) / retention | Read pasted string               | Use connection outside bot                            | Immediate delete, dedicated budgeted connection, NWC-08 follow-up                               | Until user deletes connection                              |
| Incoming updates        | Bot-token thief                | Race getUpdates                  | Read pasted strings/PIN taps; impersonate bot         | Token via secret file, never logged; revoke in BotFather                                        | Window until revoked                                       |
| Payments                | Relay                          | Drop/delay/replay                | DoS; no forgery                                       | Signatures, e/p/author checks, `expiration`, wallet dedupe                                      | DoS                                                        |
| Payments                | Bug/race                       | Double confirm                   | Double pay                                            | CAS, 1 in-flight, hash uniqueness, wallet idempotency, no retries                               | Low                                                        |
| Other users' wallets    | Malicious user                 | Forge callback ids               | Cross-user access                                     | Random ids + `user_id` check on every lookup                                                    | —                                                          |
| Bot host network        | Malicious user                 | `relay=` to internal URL         | SSRF                                                  | Relay allowlist, wss only                                                                       | —                                                          |
| User                    | Scammer                        | Malicious invoice / fake support | Pays attacker                                         | Confirmation with amount, memo labelled as recipient-written, PIN, help warnings                | Social engineering remains possible                        |
| Bot                     | Spammer                        | Flood commands                   | Resource use, phone push spam                         | Rate limits, caps                                                                               | —                                                          |

## 14. Commands (Telegram UX)

`/start` welcome + status · `/connect` pairing link (NWC-08) ·
`/balance` ·
`/receive <sats> [memo]` · `/send` (or just paste an invoice) ·
`/transactions` · `/status` · `/reconnect` · `/disconnect` · `/help`.
User-facing language avoids NWC jargon ("Wallet Connect", "connection",
"connection string" — the terms the Blitz app uses).

## 15. Reference implementation review (musa-42/Zap_lnbot)

Useful: inline-keyboard menus; confirmation step before paying; private-chat
filter; owner check on confirmation callbacks; expiring pending confirmations.

Avoid / security weaknesses:

- **Custodial**: it generates and stores users' BIP39 mnemonics in plaintext
  SQLite on the bot server — a server or backup leak loses all users' funds.
  Our design holds no keys and only a budget-bounded, revocable credential.
- Displays the seed phrase in chat ("Backup") and accepts seed import via chat
  messages — secrets permanently in Telegram history.
- Pending payment state is in a per-user dict: the Confirm button pays whatever
  was prepared _last_, not what that message showed; lost on restart.
- Exceptions are shown to users verbatim and any exception after send is
  reported as "Payment Failed" (unknown treated as failed).
- Group tipping (`/zap` in groups) — out of scope; exposes activity to group.
- Not carried over: custody, seed backup/restore, on-chain, fiat rate fetching,
  group zaps, lightning address management.

Architectural difference: Zap_lnbot runs the wallet (Breez SDK) inside the bot;
here the wallet runs on the user's phone and the bot is a thin NWC client.

## 16. Follow-ups requiring human decision

1. ~~NWC-08 in Blitz~~ — done (§18). Remaining: publish `/nwc/*` in the
   `blitzwallet.app` AASA file so iOS opens the link in the app.
2. Blitz `payment_received` notifications (NWC-02) — replaces invoice polling.
3. Blitz `get_budget` — lets the bot refuse connections without a budget.
4. QR codes for invoices (needs an image dependency).

## 17. Post-implementation security review

Performed after the code was written, by walking each attacker position to
"unauthorized fund movement" and by searching the code for the classes listed
in the brief.

**Fixed during review**

- Connection strings in photo captions or **edited** messages were not deleted
  → `edited_message` is now subscribed; text and captions are screened; edits
  never execute commands.
- Rotation query used `LIKE 'v1.<id>.%'`; `_` in a key id is a wildcard →
  replaced with an exact prefix comparison.
- Unlimited pending confirmations per user (DB growth via invoice spam) → one
  pending confirmation per user.
- A confirmation created under a replaced connection could be paid by the new
  one → replacing a connection cancels pending confirmations and keypads.
- Recipient memos could use bidi-override characters to visually spoof the
  confirmation screen → control/bidi characters stripped, then HTML-escaped.
- Non-allowlisted users were not rate-limited → rate limit applies first.
- Uncaught errors would print raw stacks to stderr → routed through the
  redacting logger.
- "Still unknown after 3 days" could be re-sent on every manual refresh →
  sent once.

**Checked, no issue found**

- Secret leakage: secrets only exist decrypted in memory for a request; never
  in logs (tests assert this with the real secret, PIN and connection string),
  user messages, URLs (the bot token is in the Telegram API URL path, which is
  never logged; fetch errors are replaced), CLI args, temp files (none),
  telemetry/crash reports (none). `*_FILE` variants keep secrets out of env.
- Plaintext storage: only AES-256-GCM ciphertext with row-bound AAD.
- AuthN/AuthZ and cross-user access: every row lookup includes `user_id =
from.id`; callback data is strictly parsed and holds 128-bit random ids;
  callbacks from non-private chats are ignored; keypad sessions are per user
  with a random nonce and message-id binding.
- Telegram identity confusion: only `from.id` is trusted; usernames unused;
  groups refused and left.
- Replay: request ids are unique signed events with `expiration`; Blitz
  dedupes ids and enforces a 300 s freshness window; responses must match our
  request id, author and `p` tag and carry a valid signature.
- Double payments / races / missing locks: CAS in one SQL statement; per-user
  update serialization; one in-flight payment; hash uniqueness; no retry code
  path exists (tests assert one `pay_invoice` across reconciliation and
  restart).
- Weak randomness: `crypto.randomBytes` / nostr-tools CSPRNG only.
- SQL injection: all statements parameterized (the only interpolations are the
  migration integer and a length/prefix passed as parameters).
- Command injection / unsafe deserialization: no shell, no `eval`; only
  `JSON.parse` on decrypted, authenticated wallet payloads with size caps.
- SSRF: relay URLs from user input must be on `ALLOWED_RELAYS` (`wss://`
  only), enforced at parse time and again before every request.
- Dependencies: `npm audit` reports 0 vulnerabilities; two runtime deps, both
  already used by Blitz Wallet.

**Assumptions the safety argument rests on (verify if they change)**

- The wallet honors the request `expiration` tag. Blitz does (JS, Android and
  iOS handlers). The "NOT_FOUND after expiration + grace ⇒ not sent" rule
  depends on it; it is also why connections are limited to allowlisted relays.
- The wallet records an outgoing payment before sending it (Blitz claims the
  payment hash first), so a payment in progress is visible to `lookup_invoice`.
- Server clock is NTP-synced (Blitz rejects events more than 300 s off).
- Exactly one bot process per database and bot token.

**Residual risks** (accepted, documented): live server or DB+key compromise
can spend up to every user's Blitz budget; the pasted connection string may be
retained by Telegram until NWC-08 pairing exists; social engineering of users
into confirming malicious invoices; relay/phone availability (DoS) leaves
payments "unknown" for a while.

## 18. NWC-08 pairing (implemented)

**Why:** with the paste flow the client secret is generated by Blitz and then
travels through the clipboard and Telegram. With NWC-08 the bot generates the
key; only public keys and a one-time `state` cross any channel. The secret
exists only in bot memory until approval, then only encrypted in the DB.

**Flow**

1. `/connect`: bot creates a keypair and a 128-bit `state`, keeps the secret in
   memory (not the DB), and sends a button to
   `https://blitzwallet.app/nwc/auth?pubkey=…&relay=…&state=…&name=Telegram @bot&request_methods=get_info get_balance make_invoice lookup_invoice list_transactions&optional_request_methods=pay_invoice&max_amount=<CONNECT_MONTHLY_BUDGET_SATS×1000>&renewal_period=monthly`.
   The same parameters are shown as a `nostr+walletauth://` URI for scanning on
   another device. Telegram buttons only open http(s) links, hence the app link.
2. Blitz shows an approval screen: unverified app name, required permissions,
   "Send payments" as an optional toggle (on by default), and the monthly limit.
   The spec rules are enforced in Blitz: every required method granted or the
   request is declined; nothing unrequested is granted; a requested limit is
   enforced (rounded down to sats) or the request is declined.
3. On approval Blitz stores a connection keyed to the bot's public key (no
   secret on the phone) and publishes its 13194 info event with
   `["p", botKey]`, `["state", state]` and `["relay", blitzRelay]`.
4. The bot, subscribed to `{kinds:[13194], #p:[botKey]}`, accepts the event
   only with a valid signature, matching `p` and `state`, and relays on its
   allowlist. The signer becomes the wallet pubkey; granted methods come from
   the event content. No `get_info` round trip, because the push backend can
   take a few seconds to start routing a new connection.

**Properties**

- Links expire after 15 minutes; a new `/connect` or `/disconnect` cancels the
  pending one; at most one per user and 1000 globally. A restart forgets
  pending links — an approval that arrives later creates a connection in Blitz
  whose secret no longer exists anywhere (useless to everyone; the user
  deletes it).
- `state` is the only thing stopping someone else's wallet from answering
  first (the wallet key is learned from the signer). It is 128 random bits,
  appears only in the link, and is single-use.
- Connection switching is refused while a payment is unconfirmed, both when the
  link is created and when the approval arrives.
- Residual: someone who can read the user's Telegram chat within the 15-minute
  window could approve the link with _their_ wallet, pointing the user's bot
  at a wallet the attacker controls (the user's own funds are not exposed;
  invoices created afterwards would pay the attacker). Anyone with that access
  can already drive the bot, so this adds little.

**Blitz changes** (BlitzWallet repo): `app/functions/nwc/walletAuth.js`
(parser), `saveNWCAccount` (client key, tagged info event, no secret), approval
screen `nwcAuthApproval.js`, deep-link branch in `App.tsx`, scan/paste
redirect, `nostr+walletauth` schemes and the `/nwc/auth` app link, account
page hides "Connection string" for these connections.
Known deviation: Blitz publishes `payment_sent` notifications for any
connection that can send, including ones that did not request
`notification_types` (gating it needs native handler changes). The bot does not
request notifications.

**NWC backend:** no routing change needed (it routes by wallet pubkey, still
generated by Blitz). Fixed a latency bug: the Firestore change debounce was
reset on every change, so steady churn could postpone subscribing a new
connection indefinitely; it now processes at most 10 s after the first change.

## 19. Inline mode (invoices in any chat)

`@bot <sats> [memo]` in any chat. Typing only previews: Telegram sends a query
per keystroke and every wallet call wakes the phone, so no wallet call happens
until the user picks the result (`chosen_inline_result`, which needs BotFather
`/setinlinefeedback`). The bot then re-parses the query (the preview is not
trusted), creates the invoice in the picker's own wallet (`from.id`), and edits
the posted message to contain it. Answers use `is_personal: true` and
`cache_time: 0` so Telegram never serves one user's result to another. Only
`make_invoice` is reachable this way; balance, history and payments stay in the
private chat. Errors are posted in the chat only as a short notice, and the
reason goes to the requester privately. Same caps as `/receive` (wallet rate
limit, 5 open invoices).

**Paying posted invoices.** Invoices posted this way carry a "⚡ Pay with
Blitz" button (`ip:<invoice id>`). Pressing it never pays: the bot answers the
callback with a `t.me/<bot>?start=pay_<id>` link, which opens the presser's
private chat, where the normal send flow (validation, Confirm, PIN, CAS, no
retries) runs on that invoice. Confirmation and PIN entry therefore never
happen in a shared chat. The posted invoice's BOLT11 text is kept only while it
is open (migration 2) because inline callbacks don't include the message text.
When a payment through the bot settles a posted invoice, the requester's
invoice is reconciled immediately and the posted message is edited to "paid"
(or "expired"). Paying your own invoice is refused. Inline _queries_ can't be
used to pay pasted invoices: Telegram caps queries at 256 characters, shorter
than most BOLT11 invoices.

**Posted request layout.** The posted message shows the sender's Telegram name,
amount and memo only; the BOLT11 text lives in the buttons: "⚡ Pay request" and, when the
bot knows its username, "Pay with @bot". Telegram buttons can only open
`http(s)`/`tg` links, so "⚡ Pay request" links to
`https://blitzwalletapp.com/pay#open:<invoice>`. That page (blitz-wallet-website `pages/pay/`) reads the
invoice from the URL fragment, which browsers never send to the server,
validates it as bech32 BOLT11, then hands it to `lightning:` / the clipboard and
shows a QR for desktop users. It has no analytics. The inline result thumbnail is the website's 512 px icon.
