import { setTimeout as sleep } from 'node:timers/promises';

// Minimal Telegram Bot API client over fetch. The token lives in the request
// URL, so URLs are never logged and errors carry only Telegram's description.
export class TelegramError extends Error {
  constructor(method, code, description) {
    super(`Telegram ${method} failed (${code}): ${description}`);
    this.code = code;
    this.retryAfter = null;
  }
}

export function createTelegram({ token, fetchImpl = fetch, log }) {
  const base = `https://api.telegram.org/bot${token}/`;

  async function call(
    method,
    params = {},
    { timeoutMs = 15_000, signal } = {},
  ) {
    const timeout = AbortSignal.timeout(timeoutMs);
    let res;
    try {
      res = await fetchImpl(base + method, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(params),
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      });
    } catch (err) {
      // fetch errors can embed the URL; rethrow a clean one.
      throw new TelegramError(
        method,
        err.name === 'AbortError' || err.name === 'TimeoutError'
          ? 'timeout'
          : 'network',
        'request failed',
      );
    }
    const body = await res.json().catch(() => null);
    if (!body?.ok) {
      const err = new TelegramError(
        method,
        body?.error_code ?? res.status,
        body?.description ?? 'bad response',
      );
      err.retryAfter = body?.parameters?.retry_after ?? null;
      throw err;
    }
    return body.result;
  }

  // Long polling: no inbound port, no webhook secret to manage. The offset
  // acknowledges updates, so Telegram redelivers whatever we had not
  // acknowledged before a crash; handlers are idempotent where it matters.
  // A 409 Conflict means another client is polling with the same token
  // (or a webhook is diverting updates to an attacker's server). That is a
  // security alarm, not an ordinary warning: with the token an attacker can
  // impersonate the bot during /connect and serve their own pairing link.
  async function poll(onUpdate, signal) {
    let offset = 0;
    let backoff = 1000;
    while (!signal.aborted) {
      try {
        const updates = await call(
          'getUpdates',
          {
            offset,
            timeout: 30,
            allowed_updates: [
              'message',
              'edited_message',
              'callback_query',
              'inline_query',
              'chosen_inline_result',
            ],
          },
          { timeoutMs: 40_000, signal },
        );
        backoff = 1000;
        for (const update of updates) {
          offset = Math.max(offset, update.update_id + 1);
          onUpdate(update);
        }
      } catch (err) {
        if (signal.aborted) break;
        const wait = err.retryAfter ? err.retryAfter * 1000 : backoff;
        if (Number(err.code) === 409) {
          // Log every time (not just the first): this needs an operator.
          log.error(
            'telegram 409 Conflict: another getUpdates client or a webhook is active. Possible token compromise — revoke the token via @BotFather if unexpected, then check getWebhookInfo',
            { err, waitMs: wait },
          );
        } else {
          log.warn('telegram poll failed', { err, waitMs: wait });
        }
        await sleep(wait, undefined, { signal }).catch(() => {});
        backoff = Math.min(backoff * 2, 60_000);
      }
    }
  }

  // An attacker with the token can set a webhook so this poller goes deaf
  // while users keep talking to "the bot". Call at startup and on a timer;
  // any non-empty url is a security alarm.
  async function checkWebhook() {
    let info;
    try {
      info = await call('getWebhookInfo', {}, { timeoutMs: 15_000 });
    } catch (err) {
      log.warn('getWebhookInfo failed', { err });
      return null;
    }
    if (info?.url) {
      log.error(
        'telegram webhook is active while polling: updates may be diverted to another server. Possible token compromise — revoke the token via @BotFather if unexpected',
        { url: info.url },
      );
    }
    return info;
  }

  return { call, poll, checkWebhook };
}
