/**
 * BANKISM Deterministic Authorization Gate & Mock Ledger
 * 
 * Enforces server-side cryptographic token verification (HMAC-SHA256),
 * atomic idempotency, token single-use replay prevention, and isolated mock ledger accounting.
 * Client-side state cannot bypass this gate.
 */

import crypto from 'node:crypto';
import { MockTransaction, ExecuteTransferPayload, FirewallVerdict } from '../types/firewall';
import { CONFIG } from './policyEngine';
import { DEMO_RECIPIENTS } from './threatScanner';

export interface LedgerState {
  current_balance: number;
  transactions: MockTransaction[];
}

export interface StorageBackendInfo {
  type: 'LOCAL_IN_MEMORY_DEMO';
  multiInstanceConsistent: boolean;
  note: string;
}

interface TokenPayload {
  rid: string;
  rec: string;
  amt: number;
  memo: string;
  v: 'APPROVED';
  intent: 'TRANSFER';
  iat: number;
  exp: number;
}

/**
 * Get secret signing key for HMAC-SHA256 authorization tokens.
 * In production mode, an explicit FIREWALL_SIGNING_KEY of at least 32 characters is required.
 * In development and automated test modes, an explicit development fallback is used.
 */
export function getSigningKey(): string {
  const key = process.env.FIREWALL_SIGNING_KEY;
  if (!key) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('SECURITY_ERROR: Missing mandatory FIREWALL_SIGNING_KEY environment variable in production mode.');
    }
    return 'bankism_dev_only_ephemeral_signing_key_soc_2026_min_32_chars';
  }
  if (process.env.NODE_ENV === 'production') {
    if (key === 'bankism_dev_only_ephemeral_signing_key_soc_2026_min_32_chars') {
      throw new Error('SECURITY_ERROR: Insecure development fallback key cannot be used in production mode.');
    }
    if (key.length < 32) {
      throw new Error('SECURITY_ERROR: FIREWALL_SIGNING_KEY must be at least 32 characters long in production mode.');
    }
  }
  return key;
}

/**
 * Mint a stateless, cryptographically signed HMAC-SHA256 authorization token
 * for an approved transfer verdict.
 */
export function signVerdictToken(verdict: FirewallVerdict): string {
  if (verdict.verdict !== 'APPROVED' || verdict.intent !== 'TRANSFER') {
    throw new Error('SECURITY_ERROR: Cannot sign authorization token for unapproved or non-transfer verdict.');
  }

  const recipient = verdict.extracted_parameters?.recipient;
  const amount = verdict.extracted_parameters?.amount;
  const memo = (verdict.extracted_parameters?.memo || '').trim();

  if (!recipient || amount === undefined || amount <= 0 || !Number.isFinite(amount)) {
    throw new Error('SECURITY_ERROR: Cannot sign authorization token with missing or invalid parameters.');
  }

  const key = getSigningKey();
  const now = Date.now();
  const payload: TokenPayload = {
    rid: verdict.request_id,
    rec: recipient,
    amt: amount,
    memo,
    v: 'APPROVED',
    intent: 'TRANSFER',
    iat: now,
    exp: now + 5 * 60 * 1000, // 5-minute validity window
  };

  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', key).update(payloadB64).digest('hex');

  return `bk_auth.${payloadB64}.${signature}`;
}

/**
 * Verify a signed HMAC-SHA256 verdict token against expected execution parameters.
 * Validates cryptographic signature, expiration, request binding, recipient, amount, and memo.
 */
export function verifyVerdictToken(
  token: string,
  expected: { request_id: string; recipient: string; amount: number; memo?: string }
): { valid: boolean; error?: string; payload?: TokenPayload } {
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'GATE_REJECTION: Missing authorization token.' };
  }

  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'bk_auth') {
    return { valid: false, error: 'GATE_REJECTION: Malformed authorization token structure.' };
  }

  const [, payloadB64, receivedSig] = parts;

  let key: string;
  try {
    key = getSigningKey();
  } catch (err: any) {
    return { valid: false, error: `GATE_REJECTION: ${err.message}` };
  }

  // Recompute expected HMAC signature
  const expectedSig = crypto.createHmac('sha256', key).update(payloadB64).digest('hex');

  // Constant-time signature comparison to prevent timing attacks
  const receivedBuf = Buffer.from(receivedSig, 'utf-8');
  const expectedBuf = Buffer.from(expectedSig, 'utf-8');

  if (receivedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(receivedBuf, expectedBuf)) {
    return { valid: false, error: 'GATE_REJECTION: Invalid token signature. Forged or tampered authorization token detected.' };
  }

  // Decode and validate payload contents
  let payload: TokenPayload;
  try {
    const rawJson = Buffer.from(payloadB64, 'base64url').toString('utf-8');
    payload = JSON.parse(rawJson);
  } catch {
    return { valid: false, error: 'GATE_REJECTION: Malformed token payload encoding.' };
  }

  // Validate expiration
  if (!payload.exp || Date.now() > payload.exp) {
    return { valid: false, error: `GATE_REJECTION: Authorization token expired at ${new Date(payload.exp || 0).toISOString()}.` };
  }

  // Validate intent and verdict
  if (payload.v !== 'APPROVED' || payload.intent !== 'TRANSFER') {
    return { valid: false, error: 'GATE_REJECTION: Token does not contain an approved transfer authorization.' };
  }

  // Validate strict parameter binding
  if (payload.rid !== expected.request_id) {
    return { valid: false, error: 'GATE_REJECTION: Token request ID does not match the submitted transaction request ID.' };
  }

  if (payload.rec !== expected.recipient) {
    return { valid: false, error: `GATE_REJECTION: Token recipient "${payload.rec}" does not match requested recipient "${expected.recipient}".` };
  }

  if (payload.amt !== expected.amount) {
    return { valid: false, error: `GATE_REJECTION: Token amount ($${payload.amt}) does not match requested amount ($${expected.amount}).` };
  }

  const expectedMemo = (expected.memo || '').trim();
  const payloadMemo = (payload.memo || '').trim();
  if (payloadMemo !== expectedMemo) {
    return { valid: false, error: `GATE_REJECTION: Token memo "${payloadMemo}" does not match requested transaction memo "${expectedMemo}".` };
  }

  return { valid: true, payload };
}

// In-memory ledger and idempotency store for demo sandbox
class MockLedgerStore {
  private balance: number = CONFIG.DEMO_ACCOUNT_INITIAL_BALANCE;
  private transactions: MockTransaction[] = [
    {
      id: 'tx_init_001',
      timestamp: new Date(Date.now() - 3600000 * 24).toISOString(),
      type: 'CREDIT',
      sender: 'Direct Deposit / Payroll',
      recipient: CONFIG.DEMO_ACCOUNT_OWNER,
      amount: 5000.0,
      memo: 'Initial demo balance funding',
      status: 'COMPLETED',
      idempotency_key: 'idem_init_001',
      request_id: 'req_system_init',
    },
  ];

  // Processed idempotency keys mapped to executed transaction
  private processedIdempotencyKeys = new Map<string, MockTransaction>();

  // Redeemed token request IDs to prevent token replay
  private redeemedTokenIds = new Set<string>();

  public getBalance(): number {
    return this.balance;
  }

  public getTransactions(): MockTransaction[] {
    return [...this.transactions];
  }

  public getStorageInfo(): StorageBackendInfo {
    return {
      type: 'LOCAL_IN_MEMORY_DEMO',
      multiInstanceConsistent: false,
      note: 'Demo sandbox running in process memory. Transaction state, ledger balances, and replay tokens are isolated to the active serverless container runtime and do not persist across separate Lambda microVM instances. Production multi-instance consistency requires connecting an external atomic store (e.g. Upstash Redis or Vercel KV).',
    };
  }

  public resetLedger(): void {
    this.balance = CONFIG.DEMO_ACCOUNT_INITIAL_BALANCE;
    this.transactions = [
      {
        id: 'tx_init_001',
        timestamp: new Date(Date.now() - 3600000 * 24).toISOString(),
        type: 'CREDIT',
        sender: 'Direct Deposit / Payroll',
        recipient: CONFIG.DEMO_ACCOUNT_OWNER,
        amount: 5000.0,
        memo: 'Initial demo balance funding',
        status: 'COMPLETED',
        idempotency_key: 'idem_init_001',
        request_id: 'req_system_init',
      },
    ];
    this.processedIdempotencyKeys.clear();
    this.redeemedTokenIds.clear();
  }

  /**
   * Register an approved verdict and mint a cryptographic authorization token.
   * Stateless: can be verified by any serverless instance without shared memory.
   */
  public registerApprovedVerdict(verdict: FirewallVerdict): string {
    return signVerdictToken(verdict);
  }

  /**
   * Authorize and execute a mock transfer.
   * Verifies cryptographic verdict token, enforces idempotency, prevents token replay,
   * checks balance, and executes ledger accounting.
   */
  public executeTransfer(payload: ExecuteTransferPayload): {
    success: boolean;
    error?: string;
    transaction?: MockTransaction;
    updated_balance: number;
  } {
    const { request_id, recipient, amount, idempotency_key, verdict_token, memo } = payload;

    // 1. Atomic Idempotency Check (Prevent duplicate execution)
    if (this.processedIdempotencyKeys.has(idempotency_key)) {
      const existingTx = this.processedIdempotencyKeys.get(idempotency_key)!;
      return {
        success: false,
        error: `DUPLICATE_REJECTED: Idempotency key "${idempotency_key}" was already executed at ${existingTx.timestamp}.`,
        transaction: existingTx,
        updated_balance: this.balance,
      };
    }

    // 2. Cryptographic Authorization Token Verification (Stateless & tamper-proof)
    const verification = verifyVerdictToken(verdict_token, {
      request_id,
      recipient,
      amount,
      memo,
    });

    if (!verification.valid) {
      return {
        success: false,
        error: verification.error || 'GATE_REJECTION: Authorization verification failed.',
        updated_balance: this.balance,
      };
    }

    // 3. Token Single-Use Replay Prevention
    if (this.redeemedTokenIds.has(request_id)) {
      return {
        success: false,
        error: `REPLAY_REJECTED: Authorization token for request ID "${request_id}" has already been redeemed. Single-use token expired.`,
        updated_balance: this.balance,
      };
    }

    // 4. Strict Recipient, Amount & Balance Invariant Check
    if (!DEMO_RECIPIENTS.includes(recipient)) {
      return {
        success: false,
        error: `GATE_REJECTION: Recipient "${recipient}" is not in the authorized demo peer directory.`,
        updated_balance: this.balance,
      };
    }

    if (amount <= 0 || !Number.isFinite(amount) || isNaN(amount)) {
      return {
        success: false,
        error: 'GATE_REJECTION: Invalid transaction amount. Must be a finite positive number.',
        updated_balance: this.balance,
      };
    }

    if (amount > CONFIG.MAX_SINGLE_TRANSFER_USD) {
      return {
        success: false,
        error: `GATE_REJECTION: Amount ($${amount}) exceeds maximum single transfer limit of $${CONFIG.MAX_SINGLE_TRANSFER_USD}.`,
        updated_balance: this.balance,
      };
    }

    if (amount > this.balance) {
      return {
        success: false,
        error: `GATE_REJECTION: Insufficient demo funds. Current balance: $${this.balance.toFixed(2)}, requested: $${amount.toFixed(2)}.`,
        updated_balance: this.balance,
      };
    }

    // 5. Execute Mock Transfer
    this.balance -= amount;

    const newTx: MockTransaction = {
      id: `tx_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      type: 'TRANSFER',
      sender: CONFIG.DEMO_ACCOUNT_OWNER,
      recipient,
      amount,
      memo: memo || 'Transfer verified by BANKISM AI Firewall',
      status: 'COMPLETED',
      idempotency_key,
      request_id,
    };

    this.transactions.unshift(newTx);
    this.processedIdempotencyKeys.set(idempotency_key, newTx);
    this.redeemedTokenIds.add(request_id);

    return {
      success: true,
      transaction: newTx,
      updated_balance: this.balance,
    };
  }
}

export const ledgerStore = new MockLedgerStore();
