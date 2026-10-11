/**
 * BANKISM Deterministic Authorization Gate & Mock Ledger
 * 
 * Enforces server-side authorization verification, idempotency duplicate prevention,
 * and isolated mock ledger accounting. Client-side state cannot bypass this gate.
 */

import { MockTransaction, ExecuteTransferPayload, FirewallVerdict } from '../types/firewall';
import { CONFIG } from './policyEngine';

export interface LedgerState {
  current_balance: number;
  transactions: MockTransaction[];
}

// In-memory ledger and idempotency store for the demo sandbox
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

  // Processed idempotency keys mapping to their transaction id
  private processedIdempotencyKeys = new Map<string, MockTransaction>();

  // Valid server-issued authorization tokens: key = token, value = FirewallVerdict
  private authorizedTokens = new Map<string, FirewallVerdict>();

  public getBalance(): number {
    return this.balance;
  }

  public getTransactions(): MockTransaction[] {
    return [...this.transactions];
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
    this.authorizedTokens.clear();
  }

  /**
   * Mint a tamper-evident server-side authorization token for an approved verdict
   */
  public registerApprovedVerdict(verdict: FirewallVerdict): string {
    const raw = `${verdict.request_id}:${verdict.extracted_parameters?.recipient}:${verdict.extracted_parameters?.amount}`;
    // Generate simple deterministic token hash for demo
    const token = `bk_auth_tok_${Buffer.from(raw).toString('base64')}_${Date.now().toString(36)}`;
    this.authorizedTokens.set(token, verdict);
    return token;
  }

  /**
   * Authorize and execute a mock transfer
   */
  public executeTransfer(payload: ExecuteTransferPayload): {
    success: boolean;
    error?: string;
    transaction?: MockTransaction;
    updated_balance: number;
  } {
    const { request_id, recipient, amount, idempotency_key, verdict_token, memo } = payload;

    // 1. Idempotency Check (Prevent duplicate execution)
    if (this.processedIdempotencyKeys.has(idempotency_key)) {
      const existingTx = this.processedIdempotencyKeys.get(idempotency_key)!;
      return {
        success: false,
        error: `DUPLICATE_REJECTED: Idempotency key "${idempotency_key}" was already executed at ${existingTx.timestamp}.`,
        transaction: existingTx,
        updated_balance: this.balance,
      };
    }

    // 2. Server-side Authorization Token Verification (Prevents UI bypass)
    const verifiedVerdict = this.authorizedTokens.get(verdict_token);
    if (!verifiedVerdict) {
      return {
        success: false,
        error: 'GATE_REJECTION: Missing or forged server authorization token. Client-state tampering detected.',
        updated_balance: this.balance,
      };
    }

    // 3. Strict Schema and Parameter Match
    if (verifiedVerdict.verdict !== 'APPROVED') {
      return {
        success: false,
        error: `GATE_REJECTION: Request verdict was "${verifiedVerdict.verdict}". Privileged transaction halted.`,
        updated_balance: this.balance,
      };
    }

    if (
      verifiedVerdict.extracted_parameters?.recipient !== recipient ||
      verifiedVerdict.extracted_parameters?.amount !== amount
    ) {
      return {
        success: false,
        error: 'GATE_REJECTION: Transaction parameters do not match verified server authorization token.',
        updated_balance: this.balance,
      };
    }

    // 4. Balance & Limit Check
    if (amount <= 0 || !Number.isFinite(amount)) {
      return {
        success: false,
        error: 'GATE_REJECTION: Invalid transaction amount.',
        updated_balance: this.balance,
      };
    }

    if (amount > this.balance) {
      return {
        success: false,
        error: `GATE_REJECTION: Insufficient demo funds. Current balance: $${this.balance}, requested: $${amount}.`,
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

    // Invalidate single-use token to prevent replay
    this.authorizedTokens.delete(verdict_token);

    return {
      success: true,
      transaction: newTx,
      updated_balance: this.balance,
    };
  }
}

export const ledgerStore = new MockLedgerStore();
