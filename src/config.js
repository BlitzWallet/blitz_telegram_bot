import { readFileSync } from 'node:fs';
import 'dotenv/config';

export const BLITZ_RELAY = 'wss://relay.getalbypro.com/blitz';

// Secrets may come from `<NAME>_FILE` (Docker/K8s secrets) so they stay out of
// the process environment, which other processes of the same user can read.
function readSecret(env, name) {
  const file = env[`${name}_FILE`];
  if (file) return readFileSync(file, 'utf8').trim();
  return env[name]?.trim();
}

function int(env, name, fallback, min, max) {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

// Throws on any invalid value: the bot must not start half-configured.
export function loadConfig(env = process.env) {
  const telegramToken = readSecret(env, 'TELEGRAM_BOT_TOKEN');
  if (!telegramToken || !/^\d+:[A-Za-z0-9_-]{30,}$/.test(telegramToken)) {
    throw new Error(
      'TELEGRAM_BOT_TOKEN (or TELEGRAM_BOT_TOKEN_FILE) is missing or malformed',
    );
  }

  // "id:base64key,id:base64key" — the first key encrypts, all keys decrypt.
  const keysRaw = readSecret(env, 'ENCRYPTION_KEYS');

  if (!keysRaw)
    throw new Error('ENCRYPTION_KEYS (or ENCRYPTION_KEYS_FILE) is required');
  const encryptionKeys = keysRaw.split(',').map(entry => {
    const [id, b64] = entry.trim().split(':');
    const key = Buffer.from(b64 || '', 'base64');
    if (!/^[A-Za-z0-9_-]{1,16}$/.test(id || '') || key.length !== 32) {
      throw new Error(
        'ENCRYPTION_KEYS entries must be "<id>:<base64 of 32 random bytes>"',
      );
    }
    return { id, key };
  });
  if (new Set(encryptionKeys.map(k => k.id)).size !== encryptionKeys.length) {
    throw new Error('ENCRYPTION_KEYS ids must be unique');
  }

  const allowedRelays = (env.ALLOWED_RELAYS || BLITZ_RELAY)
    .split(',')
    .map(r => r.trim())
    .filter(Boolean);
  for (const relay of allowedRelays) {
    if (!relay.startsWith('wss://'))
      throw new Error('ALLOWED_RELAYS must be wss:// URLs');
  }

  const allowedUsers = (env.ALLOWED_TELEGRAM_USER_IDS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(Number);
  if (allowedUsers.some(id => !Number.isSafeInteger(id) || id <= 0)) {
    throw new Error(
      'ALLOWED_TELEGRAM_USER_IDS must be comma-separated numeric Telegram user ids',
    );
  }

  return {
    telegramToken,
    encryptionKeys,
    allowedRelays,
    allowedUsers: allowedUsers.length ? new Set(allowedUsers) : null,
    databasePath: env.DATABASE_PATH || './data/bot.db',
    maxPaymentSats: int(env, 'MAX_PAYMENT_SATS', 1_000_000, 1, 100_000_000),
    // Daily spending limit the bot asks Blitz for when pairing (0 = none).
    connectBudgetSats: int(
      env,
      'CONNECT_DAILY_BUDGET_SATS',
      100_000,
      0,
      100_000_000,
    ),
    logLevel: ['debug', 'info', 'warn', 'error'].includes(env.LOG_LEVEL)
      ? env.LOG_LEVEL
      : 'info',
  };
}
