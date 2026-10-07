# Bot copy guide

Rules for every user-facing string in `locales/en.json`. Other locales
translate from English.

## Words

| Say | Meaning | Don't say |
| --- | --- | --- |
| **the Blitz app** | The mobile app where the user approves and manages connections | Blitz Wallet, your Blitz app, Blitz (alone) |
| **Wallet Connect account** | The account in the Blitz app the bot uses; holds the money the bot can see and spend. Short form on buttons: "account" | wallet, your Blitz, main wallet (except to contrast with it) |
| **Wallet Connect balance** | What `/balance` shows | balance in Blitz |
| **connection** | The permission link between the bot and the Wallet Connect account | code (except for a pasted secret connection string) |
| **payment request** | A Lightning invoice. "Request" alone only where space is tight | invoice, code, long code |
| **Ask for money** | Creating a payment request | request money, ask someone to pay you |
| **approve** | What the user does in the Blitz app | say yes |
| **Cancel** / "Cancelled." | Every cancel button and its result | Stop, Stopped |

## Patterns

- Point to a command as **"To ⟨goal⟩, use /command."** Connecting goes to `/connect`, never `/start`.
- Waiting: **"Try again in a moment."**
- Errors: first person, no "Oops" or "Sorry", always say what to do next.
- Anything about money not moving ends with **"No money was sent."**
- Buttons use sentence case and no emoji (except the ⏳ placeholder button).
- Emoji only at the start of a message, only these: ✅ done, ❌ failed, ⏳ waiting, ⚠️ warning.
- Menu paths come from `$t(paths.both)`, never typed out.
- `/help` and the command menu (`setMyCommands` in `src/index.js`) list the same commands in the same order with the same descriptions.
