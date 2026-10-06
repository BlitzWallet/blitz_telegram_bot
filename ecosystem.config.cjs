/**
 * pm2 process config for the bot. Single app, fork mode.
 *
 * Exactly one instance per bot token: Telegram allows one getUpdates consumer
 * and the payment CAS is per-database. Never use cluster mode or instances > 1.
 *
 *   Start:   npm run start:pm2     (or: pm2 start ecosystem.config.cjs)
 *   Logs:    pm2 logs blitz-telegram-bot
 *   Save:    pm2 save && pm2 startup   (to survive reboots)
 */
module.exports = {
  apps: [
    {
      name: 'blitz-telegram-bot',
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
