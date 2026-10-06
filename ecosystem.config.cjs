/**
 * pm2 process config for the bot. Single app, fork mode.
 *
 * Exactly one instance per bot token: Telegram allows one getUpdates consumer
 * and the payment CAS is per-database. Never use cluster mode or instances > 1.
 *
 *   First time: cd ~/blitz_telegram_bot && pm2 start ecosystem.config.cjs && pm2 save
 *   Then:       pm2 start|restart|logs blitz_telegram_bot   (from any directory)
 *   Reboots:    pm2 startup   (once)
 *
 * The name matches the folder, so `pm2 start blitz_telegram_bot` finds this
 * registered app. Unregistered, pm2 treats it as the folder and runs
 * index.cjs with default settings (works, but without the ones below).
 */
module.exports = {
  apps: [
    {
      name: 'blitz_telegram_bot',
      script: 'src/index.js',
      // .env and the default DATABASE_PATH (./data/bot.db) are cwd-relative.
      cwd: __dirname,
      node_args: '--disable-warning=ExperimentalWarning',
      exec_mode: 'fork',
      instances: 1,
      autorestart: true,
      max_restarts: 50,
      exp_backoff_restart_delay: 1000,
      max_memory_restart: '300M',
      // Shutdown drains in-flight work for up to 10 s before closing the DB.
      kill_timeout: 12000,
      env: {
        NODE_ENV: 'production',
      },
    },
  ],
};
