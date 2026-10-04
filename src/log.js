import { createHmac } from 'node:crypto';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

// Last line of defense: callers never pass secrets, but anything that slips
// through (e.g. inside an error message) is scrubbed before it hits stdout.
const REDACTIONS = [
  [/nostr\+walletconnect:\/?\/?[^\s"']*/gi, '[nwc-uri]'],
  [/\bln(bc|tb|bcrt|tbs)[0-9a-z]{20,}/gi, '[invoice]'],
  [/\b\d{6,}:[A-Za-z0-9_-]{30,}/g, '[bot-token]'],
  [/\b[0-9a-f]{64}\b/gi, '[hex64]'],
];

export function redact(text) {
  let out = String(text);
  for (const [pattern, replacement] of REDACTIONS)
    out = out.replace(pattern, replacement);
  return out;
}

export function createLogger({
  level = 'info',
  write = line => process.stdout.write(line + '\n'),
  pseudonymKey,
} = {}) {
  const min = LEVELS[level] ?? LEVELS.info;
  const emit = (lvl, msg, fields = {}) => {
    if (LEVELS[lvl] < min) return;
    const record = { t: new Date().toISOString(), level: lvl, msg, ...fields };
    // Errors are reduced to name + message; stacks can carry request payloads.
    for (const [k, v] of Object.entries(record)) {
      if (v instanceof Error) record[k] = `${v.name}: ${v.message}`;
    }
    write(redact(JSON.stringify(record)));
  };
  return {
    debug: (m, f) => emit('debug', m, f),
    info: (m, f) => emit('info', m, f),
    warn: (m, f) => emit('warn', m, f),
    error: (m, f) => emit('error', m, f),
    // Telegram ids are personal data; logs get a stable keyed pseudonym that
    // still lets operators correlate events for abuse handling.
    user: userId =>
      pseudonymKey
        ? createHmac('sha256', pseudonymKey)
            .update(String(userId))
            .digest('hex')
            .slice(0, 12)
        : 'user',
  };
}
