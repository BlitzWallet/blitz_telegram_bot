// Entry for `pm2 start <repo dir>`: pm2 require()s the folder, which can't load
// the ESM app (top-level await) directly. Run from the repo so .env and the
// default ./data/bot.db resolve here, not wherever pm2 was started.
process.chdir(__dirname);
import('./src/index.js').then(m => m.start());
