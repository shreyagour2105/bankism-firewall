/**
 * Client-safe mock ledger seed data and constants.
 * Does NOT import Node.js native libraries (such as node:crypto).
 */

import { MockTransaction } from '../types/firewall';
import { CONFIG } from './policyEngine';

export const INITIAL_MOCK_TRANSACTIONS: MockTransaction[] = [
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
