import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createLogger } from '../src/log.js';
import { createTelegram, TelegramError } from '../src/telegram.js';

const TOKEN = '123456789:AAEhBP0av28HUVnUbbbbbbbbbbbbbbbbbbbb';
const log = createLogger({ write: () => {} });

test('telegram: API errors and network failures never carry the token', async () => {
  const tg = createTelegram({
    token: TOKEN,
    log,
    fetchImpl: async () => ({
      status: 401,
      json: async () => ({
        ok: false,
        error_code: 401,
        description: 'Unauthorized',
      }),
    }),
  });
  await assert.rejects(
    tg.call('getMe'),
    err =>
      err instanceof TelegramError &&
      err.code === 401 &&
      !err.message.includes(TOKEN),
  );

  const net = createTelegram({
    token: TOKEN,
    log,
    fetchImpl: async url => {
      throw new TypeError(`fetch failed for ${url}`);
    },
  });
  await assert.rejects(
    net.call('getMe'),
    err => !err.message.includes(TOKEN) && err.code === 'network',
  );
});

test('telegram: polling advances the offset, delivers each update once, stops on abort', async () => {
  const offsets = [];
  const batches = [[{ update_id: 5 }, { update_id: 6 }], [{ update_id: 7 }]];
  const abort = new AbortController();
  const tg = createTelegram({
    token: TOKEN,
    log,
    fetchImpl: async (url, init) => {
      offsets.push(JSON.parse(init.body).offset);
      const result = batches.shift() ?? [];
      if (!batches.length && !result.length) abort.abort();
      return { status: 200, json: async () => ({ ok: true, result }) };
    },
  });
  const seen = [];
  await tg.poll(u => seen.push(u.update_id), abort.signal);
  assert.deepEqual(seen, [5, 6, 7]);
  assert.deepEqual(offsets.slice(0, 3), [0, 7, 8]);
});
