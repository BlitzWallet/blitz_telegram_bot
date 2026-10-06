import { createHmac } from 'node:crypto';
import { SimplePool } from 'nostr-tools/pool';
import { createBot } from './bot.js';
import { loadConfig } from './config.js';
import { createKeyring } from './crypto.js';
import { openDb } from './db.js';
import { t } from './i18n.js';
import { createLogger, redact } from './log.js';
import { createNwcClient } from './nwc.js';
import { createTelegram } from './telegram.js';

// Re-encrypts every stored secret and PIN hash under the primary key so old
// keys can be retired after one successful start. Also encrypts PIN hashes
// stored in plain `scrypt.` form by older versions.
export function rotateKeys(store, keyring, log) {
  let rotated = 0;
  for (const row of store.walletsNotUnderKey(keyring.primaryId)) {
    const aad = `${row.user_id}:${row.wallet_pubkey}`;
    const pinAad = `pin:${aad}`;
    const reencrypt = (blob, ad) => keyring.encrypt(keyring.decrypt(blob, ad), ad);
    try {
      store.updateSecrets(
        row.user_id,
        reencrypt(row.secret_enc, aad),
        row.pin_hash === null
          ? null
          : row.pin_hash.startsWith('scrypt.')
            ? keyring.encrypt(row.pin_hash, pinAad)
            : reencrypt(row.pin_hash, pinAad),
      );
      rotated++;
    } catch (err) {
      log.error('cannot re-encrypt wallet secret (key missing?)', {
        user: log.user(row.user_id),
        err,
      });
    }
  }
  return rotated;
}

async function main() {
  const config = loadConfig();
  const log = createLogger({
    level: config.logLevel,
    pseudonymKey: createHmac('sha256', config.encryptionKeys[0].key)
      .update('log-pseudonym')
      .digest(),
  });
  // Route anything unexpected through the redacting logger instead of Node's
  // default stack dump to stderr.
  process.on('unhandledRejection', err =>
    log.error('unhandled rejection', { err }),
  );
  process.on('uncaughtException', err => {
    log.error('uncaught exception', { err });
    process.exit(1);
  });
  const store = openDb(config.databasePath);
  const keyring = createKeyring(config.encryptionKeys);

  const rotated = rotateKeys(store, keyring, log);
  const recovered = store.recoverSubmitting(Date.now());
  log.info('starting', { rotated, recoveredPayments: recovered });

  // Pings find a silently dead socket; closing it reports every subscription
  // closed, so the NWC client reopens pairing watches and fails calls fast.
  const pool = new SimplePool({ enablePing: true });
  const nwc = createNwcClient({
    pool,
    allowedRelays: config.allowedRelays,
    log,
  });
  const tg = createTelegram({ token: config.telegramToken, log });
  const me = await tg.call('getMe');
  config.botUsername = me.username; // shown in Blitz's approval screen
  const bot = createBot({ tg, store, nwc, keyring, config, log });

  await tg.call('deleteWebhook', { drop_pending_updates: false });
  // Verify no webhook diverts updates elsewhere, then keep checking: a
  // stolen token lets an attacker set a webhook and impersonate the bot.
  await tg
    .checkWebhook?.()
    .catch(err => log.warn('webhook check failed', { err }));
  const webhookTimer = setInterval(
    () =>
      tg.checkWebhook().catch(err => log.warn('webhook check failed', { err })),
    5 * 60_000,
  );
  webhookTimer.unref?.();
  await tg
    .call('setMyCommands', {
      commands: [
        ['balance', t('commands.balance')],
        ['receive', t('commands.receive')],
        ['send', t('commands.send')],
        ['transactions', t('commands.transactions')],
        ['status', t('commands.status')],
        ['connect', t('commands.connect')],
        ['reconnect', t('commands.reconnect')],
        ['disconnect', t('commands.disconnect')],
        ['help', t('commands.help')],
        ['language', t('commands.language')],
      ].map(([command, description]) => ({ command, description })),
    })
    .catch(err => log.warn('setMyCommands failed', { err }));
  log.info('telegram ready', { bot: me.username });

  const abort = new AbortController();
  const maintenance = setInterval(() => bot.runMaintenance(), 30_000);
  bot.runMaintenance();
  const polling = tg.poll(update => bot.handleUpdate(update), abort.signal);

  let stopping = false;
  const shutdown = async signal => {
    if (stopping) return;
    stopping = true;
    log.info('shutting down', { signal });
    clearInterval(maintenance);
    clearInterval(webhookTimer);
    abort.abort();
    await polling;
    await bot.drain(10_000);
    pool.destroy();
    store.close();
    log.info('stopped');
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

export function start() {
  main().catch(err => {
    process.stderr.write(`fatal: ${redact(err.message)}\n`);
    process.exit(1);
  });
}

// pm2 runs scripts through its own wrapper (argv[1]) and passes ours in pm_exec_path.
// `pm2 start <repo dir>` goes through ../index.cjs instead, which calls start().
if (
  import.meta.url === `file://${process.env.pm_exec_path || process.argv[1]}`
) {
  start();
}
