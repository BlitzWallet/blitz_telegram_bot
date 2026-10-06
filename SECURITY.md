# Security Policy

This bot controls Lightning payments from users' Blitz Wallets. Please report
vulnerabilities privately so they can be fixed before they are public.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion.**

Email **security@blitzwalletapp.com**. Include:

- what an attacker can do, and what they need first (a Telegram account, the
  bot token, database access, a position on the relay, …)
- steps or a test that reproduces it
- the commit you tested

Please don't test against other people's wallets or the production bot. Run
your own instance (see `README.md`) with your own bot token and a Blitz
Wallet Connect account holding a small balance.

## Scope

In scope: the code in this repository: commands and callbacks, NWC pairing
and requests, payment confirmation and PIN, the payment state machine,
encryption at rest, logging and configuration.

Out of scope here (report them to the project that owns them):

- the Blitz Wallet app, including its NWC approval screen and budgets:
  <https://github.com/BlitzWallet/BlitzWallet>
- the Nostr relay, Telegram itself, and dependencies' own bugs

The threat model and accepted residual risks are in `docs/DESIGN.md` and
the "Security model" section of `README.md`. Risks listed there as accepted
are known, though a practical way to make one worse is still welcome.

## Supported versions

Only the latest commit on `main` receives fixes.
