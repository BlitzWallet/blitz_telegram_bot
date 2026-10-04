import { createHash } from 'node:crypto';
import { decode } from 'light-bolt11-decoder';

export class InvoiceError extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason; // 'invalid' | 'network' | 'no_amount' | 'expired'
  }
}

const MAX_INVOICE_LENGTH = 2048;

// Pulls a BOLT11 invoice out of user text ("lightning:" URIs included).
export function findInvoice(text) {
  const match = String(text).match(
    /(?:lightning:)?(ln(?:bc|tb|bcrt|tbs)[0-9a-z]+)/i,
  );
  return match ? match[1].toLowerCase() : null;
}

// Mainnet BOLT11 with an amount and a payment hash, not expiring within
// `marginSec`. Signature/route checks are the wallet's job.
export function decodeInvoice(invoice, nowMs = Date.now(), marginSec = 30) {
  if (typeof invoice !== 'string' || invoice.length > MAX_INVOICE_LENGTH)
    throw new InvoiceError('invalid');
  if (!invoice.startsWith('lnbc') || invoice.startsWith('lnbcrt'))
    throw new InvoiceError('network');
  let decoded;
  try {
    decoded = decode(invoice);
  } catch {
    throw new InvoiceError('invalid');
  }
  const section = name => decoded.sections.find(s => s.name === name)?.value;
  const paymentHash = section('payment_hash');
  const timestamp = section('timestamp');
  if (!/^[0-9a-f]{64}$/.test(paymentHash || '') || !Number.isInteger(timestamp))
    throw new InvoiceError('invalid');

  const amountMsat =
    section('amount') == null ? null : Number(section('amount'));
  if (amountMsat === null) throw new InvoiceError('no_amount');
  if (!Number.isSafeInteger(amountMsat) || amountMsat <= 0)
    throw new InvoiceError('invalid');

  const expiresAt = (timestamp + (decoded.expiry ?? 3600)) * 1000;
  if (expiresAt <= nowMs + marginSec * 1000) throw new InvoiceError('expired');

  return {
    invoice,
    amountMsat,
    paymentHash,
    description:
      typeof section('description') === 'string' ? section('description') : '',
    expiresAt,
  };
}

// The only acceptable proof that an outgoing payment succeeded.
export function isValidPreimage(preimage, paymentHash) {
  if (typeof preimage !== 'string' || !/^[0-9a-f]{64}$/i.test(preimage))
    return false;
  return (
    createHash('sha256').update(Buffer.from(preimage, 'hex')).digest('hex') ===
    paymentHash.toLowerCase()
  );
}
