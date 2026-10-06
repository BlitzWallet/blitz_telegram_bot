import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { hexToBytes, normalizeURL } from 'nostr-tools/utils';

const HEX64 = /^[0-9a-f]{64}$/;
const MAX_RESPONSE_CONTENT = 256 * 1024;
const PAIRING_BATCH = 100; // pending pairings per shared subscription
const RESPONDER_IDLE_MS = 30_000;

// No valid answer: the wallet didn't respond in time, or the relay closed our
// subscription. `sent` is false when the request was never published, so the
// wallet cannot have acted on it.
export class NwcTimeoutError extends Error {
  constructor(message, sent = true) {
    super(message);
    this.sent = sent;
  }
}
export class ConnectionStringError extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason; // 'invalid' | 'relay'
  }
}

export const containsConnectionString = text =>
  /nostr\+walletconnect:/i.test(String(text));

// Strict parse. Every relay must be on the allowlist: the relay URL comes from
// user input and the bot would otherwise open sockets wherever it points (SSRF).
export function parseConnectionString(text, allowedRelays) {
  const match = String(text).match(
    /nostr\+walletconnect:\/?\/?([^\s?]+)\?(\S+)/i,
  );
  if (!match) throw new ConnectionStringError('invalid');
  const walletPubkey = match[1].toLowerCase();
  const params = new URLSearchParams(match[2]);
  const secret = (params.get('secret') || '').toLowerCase();
  if (!HEX64.test(walletPubkey) || !HEX64.test(secret))
    throw new ConnectionStringError('invalid');
  try {
    getPublicKey(hexToBytes(secret)); // rejects out-of-range keys
  } catch {
    throw new ConnectionStringError('invalid');
  }

  const allowed = new Set(allowedRelays.map(normalizeURL));
  let relays;
  try {
    relays = [...new Set(params.getAll('relay').map(normalizeURL))];
  } catch {
    throw new ConnectionStringError('invalid');
  }
  if (!relays.length) throw new ConnectionStringError('invalid');
  if (!relays.every(r => allowed.has(r)))
    throw new ConnectionStringError('relay');
  return { walletPubkey, secret, relays };
}

// One client per process over a shared relay pool (nostr-tools SimplePool or a
// test double with the same subscribe/publish/get surface).
export function createNwcClient({
  pool,
  allowedRelays,
  now = () => Date.now(),
  log,
}) {
  const allowed = new Set(allowedRelays.map(normalizeURL));
  const closeReason = reasons => String(reasons?.[0]?.reason ?? 'closed');
  const checkRelays = relays => {
    if (!relays.length || !relays.every(r => allowed.has(normalizeURL(r)))) {
      throw new Error('Relay not allowed');
    }
  };

  // Prefer NIP-44; NIP-04 only when the wallet's info event says it lacks it.
  // A missing info event falls back to NIP-44 and get_info proves it works.
  async function negotiateEncryption({ walletPubkey, relays }) {
    checkRelays(relays);
    const info = await pool.get(
      relays,
      { kinds: [13194], authors: [walletPubkey] },
      { maxWait: 5000 },
    );
    if (!info || info.pubkey !== walletPubkey || !verifyEvent(info))
      return 'nip44_v2';
    const tag = info.tags.find(t => t[0] === 'encryption');
    if (!tag) return 'nip04';
    return tag[1]?.split(/\s+/).includes('nip44_v2') ? 'nip44_v2' : 'nip04';
  }

  // Checks a wallet's NWC-08 approval event: null when it isn't one for this
  // link, the connection info when it is, ConnectionStringError when the
  // wallet asks for a relay outside the allowlist.
  function readPairingEvent(ev, { clientPubkey, state, relays }) {
    const tag = name => ev.tags?.find(t => t[0] === name);
    if (
      ev.kind !== 13194 ||
      !HEX64.test(ev.pubkey || '') ||
      tag('p')?.[1] !== clientPubkey ||
      tag('state')?.[1] !== state ||
      !verifyEvent(ev)
    ) {
      return null;
    }
    // Spec: when the wallet names relays, use those instead of ours. They
    // still have to be on the allowlist.
    const named = ev.tags.filter(t => t[0] === 'relay').map(t => t[1]);
    let walletRelays = relays;
    if (named.length) {
      walletRelays = named.filter(r => {
        try {
          return allowed.has(normalizeURL(r));
        } catch {
          return false;
        }
      });
      if (!walletRelays.length) throw new ConnectionStringError('relay');
    }
    const encryption = tag('encryption');
    return {
      walletPubkey: ev.pubkey,
      relays: walletRelays,
      encryption: encryption?.[1]?.split(/\s+/).includes('nip44_v2')
        ? 'nip44_v2'
        : 'nip04',
      methods: String(ev.content).split(/\s+/).filter(Boolean),
    };
  }

  // One-shot version of waitForPairing for links without a live
  // subscription: the approval is a stored event, so a query finds it.
  // Every match is checked, so a junk event p-tagged to our key can't hide
  // the real one.
  async function findPairing(
    { clientPubkey, state, relays },
    { maxWait = 5000 } = {},
  ) {
    checkRelays(relays);
    const events = await pool.querySync(
      relays,
      { kinds: [13194], '#p': [clientPubkey] },
      { maxWait },
    );
    for (const ev of events) {
      const info = readPairingEvent(ev, { clientPubkey, state, relays });
      if (info) return info;
    }
    return null;
  }

  // Pending pairings share subscriptions of up to PAIRING_BATCH keys instead
  // of one each. One the relay closes (or a dropped socket) is reopened with
  // backoff; approvals are stored events, so the new REQ still finds one
  // that arrived meanwhile (M6).
  const pairingSubs = [];

  function watchPairing(waiter) {
    const key = waiter.relays.join(',');
    let s = pairingSubs.find(
      s => s.key === key && s.waiters.size < PAIRING_BATCH,
    );
    if (!s) {
      s = { key, relays: waiter.relays, waiters: new Map(), retries: 0 };
      pairingSubs.push(s);
    }
    s.waiters.set(waiter.clientPubkey, waiter);
    openPairingSub(s);
    return () => {
      if (s.waiters.get(waiter.clientPubkey) !== waiter) return;
      s.waiters.delete(waiter.clientPubkey);
      // A finished key stays in the filter until the batch next changes;
      // its events find no waiter.
      if (s.waiters.size) return;
      pairingSubs.splice(pairingSubs.indexOf(s), 1);
      clearTimeout(s.retry);
      const sub = s.sub;
      s.sub = null;
      sub?.close();
    };
  }

  // Replaces the batch's subscription with one for its current keys. The
  // new one opens before the old one closes, so nothing slips between them.
  function openPairingSub(s) {
    clearTimeout(s.retry);
    const old = s.sub;
    const sub = pool.subscribe(
      s.relays,
      { kinds: [13194], '#p': [...s.waiters.keys()] },
      {
        onevent: ev => {
          for (const t of ev.tags ?? [])
            if (t[0] === 'p') s.waiters.get(t[1])?.onevent(ev);
        },
        onclose: reasons => {
          if (s.sub !== sub) return; // replaced, or no longer needed
          s.sub = null;
          if (now() - s.openedAt > 60_000) s.retries = 0;
          const delay = Math.min(60_000, 1000 * 2 ** s.retries++);
          log?.warn('relay closed the pairing subscription', {
            reason: closeReason(reasons),
            retryMs: delay,
          });
          s.retry = setTimeout(() => openPairingSub(s), delay);
        },
      },
    );
    s.sub = sub;
    s.openedAt = now();
    old?.close();
  }

  // NWC-08 pairing: the bot made the key, so nothing secret is ever pasted.
  // Resolves when the wallet publishes its info event addressed to our key
  // (`p`) and echoing our `state`; the signature makes the author the wallet.
  // `state` is what stops anyone else from answering first with their key.
  function waitForPairing(
    { clientPubkey, state, relays },
    { timeoutMs, signal },
  ) {
    checkRelays(relays);
    return new Promise((resolve, reject) => {
      let unwatch;
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        unwatch?.();
        fn(value);
      };
      const onAbort = () =>
        finish(reject, new NwcTimeoutError('Pairing cancelled'));
      const timer = setTimeout(
        () => finish(reject, new NwcTimeoutError('Pairing timed out')),
        timeoutMs,
      ).unref();
      signal?.addEventListener('abort', onAbort);

      const onevent = ev => {
        let info;
        try {
          info = readPairingEvent(ev, { clientPubkey, state, relays });
        } catch (err) {
          return finish(reject, err);
        }
        if (info) finish(resolve, info);
      };
      unwatch = watchPairing({ clientPubkey, relays, onevent });
      if (settled) unwatch();
    });
  }

  const encryptFor = (conn, sk, text) =>
    conn.encryption === 'nip44_v2'
      ? nip44.encrypt(text, nip44.getConversationKey(sk, conn.walletPubkey))
      : nip04.encrypt(sk, conn.walletPubkey, text);
  const decryptFrom = (conn, sk, text) =>
    conn.encryption === 'nip44_v2'
      ? nip44.decrypt(text, nip44.getConversationKey(sk, conn.walletPubkey))
      : nip04.decrypt(sk, conn.walletPubkey, text);

  // Builds and signs a request without sending it, so callers can durably
  // record the request id before it can possibly reach the wallet.
  function buildRequest(conn, method, params, { expiresInSec = 60 } = {}) {
    const sk = hexToBytes(conn.secret);
    const expiresAt = Math.floor(now() / 1000) + expiresInSec;
    const tags = [
      ['p', conn.walletPubkey],
      ['expiration', String(expiresAt)],
    ];
    if (conn.encryption === 'nip44_v2') tags.push(['encryption', 'nip44_v2']);
    const event = finalizeEvent(
      {
        kind: 23194,
        created_at: Math.floor(now() / 1000),
        tags,
        content: encryptFor(conn, sk, JSON.stringify({ method, params })),
      },
      sk,
    );
    return { event, method, expiresAt: expiresAt * 1000 };
  }

  // Responses arrive on one subscription per client key, shared by that key's
  // calls and kept open a little after the last one, so a call doesn't cost
  // its own REQ (M6). Each call waits on its request id.
  const responders = new Map();

  function responderFor(conn, clientPubkey) {
    const key = `${clientPubkey}:${conn.walletPubkey}:${conn.relays.join(',')}`;
    let r = responders.get(key);
    if (r) {
      clearTimeout(r.idle);
      return r;
    }
    let markReady;
    r = {
      waiters: new Map(), // request id -> { onevent, onclose }
      closed: false,
      ready: new Promise(resolve => (markReady = resolve)),
      release() {
        if (r.waiters.size || r.closed) return;
        clearTimeout(r.idle);
        r.idle = setTimeout(() => {
          if (r.waiters.size) return;
          r.closed = true;
          responders.delete(key);
          r.sub.close();
        }, RESPONDER_IDLE_MS);
        r.idle.unref?.();
      },
    };
    responders.set(key, r);
    r.sub = pool.subscribe(
      conn.relays,
      { kinds: [23195], authors: [conn.walletPubkey], '#p': [clientPubkey] },
      {
        onevent: ev => {
          for (const t of ev.tags ?? [])
            if (t[0] === 'e') r.waiters.get(t[1])?.onevent(ev);
        },
        // EOSE: the relay has the subscription. A refusal (CLOSED) or a
        // failed connection also passes here, just before onclose.
        oneose: () => markReady(),
        onclose: reasons => {
          markReady();
          if (r.closed) return; // closed by us
          r.closed = true;
          clearTimeout(r.idle);
          if (responders.get(key) === r) responders.delete(key);
          const reason = closeReason(reasons);
          log?.warn('relay closed a response subscription', { reason });
          for (const w of [...r.waiters.values()]) w.onclose(reason);
        },
      },
    );
    return r;
  }

  // Resolves { result } or { error: { code, message } }; throws NwcTimeoutError
  // when no valid response arrives. Only responses that are signed by the
  // wallet, address us, reference our request and decrypt cleanly count.
  function send(conn, request, { timeoutMs = 45_000 } = {}) {
    checkRelays(conn.relays);
    const sk = hexToBytes(conn.secret);
    const clientPubkey = getPublicKey(sk);
    const { event, method } = request;
    const r = responderFor(conn, clientPubkey);

    return new Promise((resolve, reject) => {
      let settled = false;
      let sent = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        r.waiters.delete(event.id);
        r.release();
        fn(value);
      };
      const fail = message =>
        finish(reject, new NwcTimeoutError(message, sent));
      const timer = setTimeout(
        () => fail('No response from wallet'),
        timeoutMs,
      );

      const onevent = response => {
        try {
          if (
            response.kind !== 23195 ||
            response.pubkey !== conn.walletPubkey ||
            !response.tags.some(t => t[0] === 'e' && t[1] === event.id) ||
            !response.tags.some(t => t[0] === 'p' && t[1] === clientPubkey) ||
            typeof response.content !== 'string' ||
            response.content.length > MAX_RESPONSE_CONTENT ||
            !verifyEvent(response)
          ) {
            return;
          }
          const body = JSON.parse(decryptFrom(conn, sk, response.content));
          if (!body || body.result_type !== method) return;
          if (body.error && typeof body.error === 'object') {
            finish(resolve, {
              error: {
                code: String(body.error.code || 'OTHER'),
                message: String(body.error.message || ''),
              },
            });
          } else if (body.result && typeof body.result === 'object') {
            finish(resolve, { result: body.result });
          }
        } catch {
          // Undecryptable or malformed: not a valid answer; keep waiting.
        }
      };

      r.waiters.set(event.id, {
        onevent,
        onclose: reason => fail(`Relay closed the subscription: ${reason}`),
      });
      // Publish only once the relay holds the subscription: a fast response
      // can't be missed, and a refused one means the request never left.
      r.ready.then(() => {
        if (settled) return;
        if (r.closed) return fail('Relay refused the subscription');
        sent = true;
        Promise.any(pool.publish(conn.relays, event)).catch(() => {
          // Every relay refused or failed. The relay may still have stored
          // it, so this is not proof the wallet never saw it; let the
          // timeout decide.
        });
      });
    });
  }

  return {
    negotiateEncryption,
    waitForPairing,
    findPairing,
    buildRequest,
    send,
    call: (conn, method, params = {}, opts = {}) =>
      send(conn, buildRequest(conn, method, params, opts), opts),
  };
}
