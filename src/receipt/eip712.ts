import { recoverTypedDataAddress } from 'viem';
import type { Account } from 'viem/accounts';
import type { OfferPayload, ReceiptPayload, SignedOffer, SignedReceipt } from '../types.js';

/** Canonical EIP-712 material from the merged offer-receipt extension. Domain chainId is
 * hardcoded to 1 by spec (off-chain signing format; payment network lives in payload.network). */

export const RECEIPT_DOMAIN = { name: 'x402 receipt', version: '1', chainId: 1n } as const;
export const OFFER_DOMAIN = { name: 'x402 offer', version: '1', chainId: 1n } as const;

export const RECEIPT_TYPES = {
  Receipt: [
    { name: 'version', type: 'uint256' },
    { name: 'network', type: 'string' },
    { name: 'resourceUrl', type: 'string' },
    { name: 'payer', type: 'string' },
    { name: 'issuedAt', type: 'uint256' },
    { name: 'transaction', type: 'string' },
  ],
} as const;

export const OFFER_TYPES = {
  Offer: [
    { name: 'version', type: 'uint256' },
    { name: 'resourceUrl', type: 'string' },
    { name: 'scheme', type: 'string' },
    { name: 'network', type: 'string' },
    { name: 'asset', type: 'string' },
    { name: 'payTo', type: 'string' },
    { name: 'amount', type: 'string' },
    { name: 'validUntil', type: 'uint256' },
  ],
} as const;

function receiptMessage(p: ReceiptPayload) {
  return {
    version: BigInt(p.version),
    network: p.network,
    resourceUrl: p.resourceUrl,
    payer: p.payer,
    issuedAt: BigInt(p.issuedAt),
    transaction: p.transaction,
  };
}

function offerMessage(p: OfferPayload) {
  return {
    version: BigInt(p.version),
    resourceUrl: p.resourceUrl,
    scheme: p.scheme,
    network: p.network,
    asset: p.asset,
    payTo: p.payTo,
    amount: p.amount,
    validUntil: BigInt(p.validUntil),
  };
}

export async function signReceipt(payload: ReceiptPayload, account: Account): Promise<SignedReceipt> {
  if (!account.signTypedData) throw new Error('account cannot sign typed data');
  const signature = await account.signTypedData({
    domain: RECEIPT_DOMAIN,
    types: RECEIPT_TYPES,
    primaryType: 'Receipt',
    message: receiptMessage(payload),
  });
  return { format: 'eip712', payload, signature };
}

export async function signOffer(payload: OfferPayload, account: Account, acceptIndex?: number): Promise<SignedOffer> {
  if (!account.signTypedData) throw new Error('account cannot sign typed data');
  const signature = await account.signTypedData({
    domain: OFFER_DOMAIN,
    types: OFFER_TYPES,
    primaryType: 'Offer',
    message: offerMessage(payload),
  });
  return acceptIndex === undefined
    ? { format: 'eip712', payload, signature }
    : { format: 'eip712', payload, signature, acceptIndex };
}

export interface VerifyResult {
  valid: boolean;
  signer?: `0x${string}`;
  reason?: string;
}

/** Verify an EIP-712 receipt. `expectedSigner` implements the spec's payTo-key authorization
 * model; pass the seller's payTo address (or a registry-resolved key) to enforce it. */
export async function verifyReceipt(artifact: SignedReceipt, expectedSigner?: string): Promise<VerifyResult> {
  if (artifact.format !== 'eip712') return { valid: false, reason: 'jws verification not implemented in v0' };
  try {
    const signer = await recoverTypedDataAddress({
      domain: RECEIPT_DOMAIN,
      types: RECEIPT_TYPES,
      primaryType: 'Receipt',
      message: receiptMessage(artifact.payload),
      signature: artifact.signature,
    });
    if (expectedSigner && signer.toLowerCase() !== expectedSigner.toLowerCase()) {
      return { valid: false, signer, reason: 'signer does not match expected authorization key' };
    }
    return { valid: true, signer };
  } catch (e) {
    return { valid: false, reason: e instanceof Error ? e.message : 'signature recovery failed' };
  }
}
