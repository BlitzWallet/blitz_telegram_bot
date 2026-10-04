import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt,
  timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

// AES-256-GCM keyring. Blob: v1.<keyId>.<iv b64url>.<ciphertext+tag b64url>.
// `aad` binds a ciphertext to its owner row so blobs cannot be swapped.
export function createKeyring(keys) {
  const byId = new Map(keys.map(k => [k.id, k.key]));
  const primary = keys[0];

  return {
    primaryId: primary.id,
    encrypt(plaintext, aad) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', primary.key, iv);
      cipher.setAAD(Buffer.from(aad));
      const body = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final(),
        cipher.getAuthTag(),
      ]);
      return `v1.${primary.id}.${iv.toString('base64url')}.${body.toString('base64url')}`;
    },
    decrypt(blob, aad) {
      const [version, keyId, ivB64, bodyB64] = String(blob).split('.');
      const key = byId.get(keyId);
      if (version !== 'v1' || !key)
        throw new Error('Unknown ciphertext format or key id');
      const body = Buffer.from(bodyB64, 'base64url');
      const decipher = createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(ivB64, 'base64url'),
      );
      decipher.setAAD(Buffer.from(aad));
      decipher.setAuthTag(body.subarray(body.length - 16));
      return Buffer.concat([
        decipher.update(body.subarray(0, body.length - 16)),
        decipher.final(),
      ]).toString('utf8');
    },
  };
}

export async function hashPin(pin) {
  const salt = randomBytes(16);
  const hash = await scryptAsync(pin, salt, 32, SCRYPT);
  return `scrypt.${salt.toString('base64url')}.${hash.toString('base64url')}`;
}

export async function verifyPin(pin, stored) {
  const [scheme, saltB64, hashB64] = String(stored).split('.');
  if (scheme !== 'scrypt') return false;
  const expected = Buffer.from(hashB64, 'base64url');
  const actual = await scryptAsync(
    pin,
    Buffer.from(saltB64, 'base64url'),
    expected.length,
    SCRYPT,
  );
  return timingSafeEqual(actual, expected);
}

export const randomId = () => randomBytes(16).toString('base64url');
