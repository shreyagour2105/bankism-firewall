/**
 * BANKISM Serverless HTTP API Handler Integration Tests
 *
 * NOTE: Unlike the unit/helper tests in firewall.test.ts and parsing_probe.test.ts,
 * this suite explicitly invokes the actual exported HTTP request/response handler
 * functions for:
 *   - /api/analyze (handler in api/analyze.ts)
 *   - /api/execute-transfer (handler in api/execute-transfer.ts)
 *   - /api/ledger (handler in api/ledger.ts)
 *
 * It exercises real HTTP semantics:
 * 1. HTTP method enforcement (GET/PUT -> 405 Method Not Allowed, OPTIONS -> 200 CORS)
 * 2. Streaming raw request chunks and malformed JSON decoding
 * 3. 4KB maximum payload size enforcement (413 or fail-closed response)
 * 4. Production behavior when FIREWALL_SIGNING_KEY is missing (fail-closed)
 * 5. Forged, missing, and expired token rejections via execute-transfer handler
 * 6. Parameter mismatch rejection (tampered recipient, amount, memo, request_id)
 * 7. Single-use replay protection and idempotency deduplication across handler calls
 * 8. Protected /api/ledger reset enforcement via timing-safe ADMIN_RESET_TOKEN
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import crypto from 'node:crypto';
import analyzeHandler from '../../../api/analyze';
import executeTransferHandler from '../../../api/execute-transfer';
import ledgerHandler from '../../../api/ledger';
import { ledgerStore, getSigningKey } from '../transactionGate';

// ─── Test HTTP Request/Response Mock Harness ────────────────────────────────

interface MockHttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  json: () => any;
}

function invokeHandler(
  handler: (req: any, res: any) => Promise<void> | void,
  options: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    body?: any; // object (pre-parsed) or string / Buffer (streamed)
    stream?: boolean; // force streaming serialization
  }
): Promise<MockHttpResponse> {
  return new Promise((resolve) => {
    const emitter = new EventEmitter();
    const req: any = emitter;
    req.method = options.method || 'POST';
    req.url = options.url || '/';
    req.headers = { ...(options.headers || {}) };

    const resHeaders: Record<string, string> = {};
    let statusCode = 200;
    let resBody = '';

    const res: any = {
      setHeader(k: string, v: string) {
        resHeaders[k.toLowerCase()] = String(v);
      },
      writeHead(code: number, headers?: Record<string, string>) {
        statusCode = code;
        if (headers) {
          for (const [k, v] of Object.entries(headers)) {
            resHeaders[k.toLowerCase()] = String(v);
          }
        }
      },
      end(data?: any) {
        if (data) {
          resBody += typeof data === 'string' ? data : data.toString('utf-8');
        }
        resolve({
          statusCode,
          headers: resHeaders,
          body: resBody,
          json: () => {
            try {
              return JSON.parse(resBody);
            } catch {
              return null;
            }
          },
        });
      },
    };

    const isStreaming = options.stream || typeof options.body === 'string' || Buffer.isBuffer(options.body);

    if (options.body !== undefined && !isStreaming && typeof options.body === 'object') {
      req.body = options.body;
    }

    Promise.resolve(handler(req, res)).catch((err) => {
      resolve({
        statusCode: statusCode === 200 ? 500 : statusCode,
        headers: resHeaders,
        body: JSON.stringify({ error: err.message }),
        json: () => ({ error: err.message }),
      });
    });

    if (isStreaming) {
      const dataStr = typeof options.body === 'object'
        ? JSON.stringify(options.body)
        : String(options.body ?? '');
      setImmediate(() => {
        emitter.emit('data', Buffer.from(dataStr));
        emitter.emit('end');
      });
    }
  });
}

// ─── SUITE 1: /api/analyze Handler Tests ────────────────────────────────────

describe('HTTP Handler Integration — /api/analyze', () => {
  it('Returns 405 Method Not Allowed on GET request', async () => {
    const res = await invokeHandler(analyzeHandler, { method: 'GET' });
    expect(res.statusCode).toBe(405);
    expect(res.json()?.error).toBe('Method Not Allowed');
  });

  it('Responds 200 to CORS OPTIONS preflight', async () => {
    const res = await invokeHandler(analyzeHandler, { method: 'OPTIONS' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('*');
    expect(res.headers['access-control-allow-methods']).toContain('POST');
  });

  it('Fails closed when streaming malformed JSON body', async () => {
    const res = await invokeHandler(analyzeHandler, {
      method: 'POST',
      body: '{"raw_input": "incomplete json ...',
    });
    // In /api/analyze, JSON parse error is caught and converted to fail-closed verdict
    expect(res.statusCode).toBe(200);
    const data = res.json();
    expect(data?.verdict?.verdict).toBe('BLOCKED');
    expect(data?.verdict?.engine_mode).toBe('FAIL_CLOSED');
    expect(data?.verdict?.rationale).toContain('FAIL-CLOSED ACTIVATED');
  });

  it('Rejects oversized payload (>4KB) and fails closed', async () => {
    const giantInput = 'A'.repeat(5000);
    const res = await invokeHandler(analyzeHandler, {
      method: 'POST',
      body: { raw_input: giantInput },
    });
    expect(res.statusCode).toBe(200);
    const data = res.json();
    expect(data?.verdict?.verdict).toBe('BLOCKED');
    expect(data?.verdict?.rationale).toContain('maximum');
  });

  it('Processes valid transfer request and returns verdict with verdict_token', async () => {
    const res = await invokeHandler(analyzeHandler, {
      method: 'POST',
      body: {
        raw_input: 'Transfer $100 to alice.eth for dinner',
        recipient: 'alice.eth',
        amount: 100,
        memo: 'dinner',
      },
    });

    expect(res.statusCode).toBe(200);
    const data = res.json();
    expect(data?.verdict?.verdict).toBe('APPROVED');
    expect(data?.verdict?.intent).toBe('TRANSFER');
    expect(data?.verdict_token).toBeDefined();
    expect(data?.verdict_token).toMatch(/^bk_auth\./);
  });
});

// ─── SUITE 2: /api/execute-transfer Handler Tests ───────────────────────────

describe('HTTP Handler Integration — /api/execute-transfer', () => {
  beforeEach(() => {
    ledgerStore.resetLedger();
  });

  it('Returns 405 Method Not Allowed on GET request', async () => {
    const res = await invokeHandler(executeTransferHandler, { method: 'GET' });
    expect(res.statusCode).toBe(405);
  });

  it('Rejects oversized payload (>4KB) with HTTP 413', async () => {
    const giantPayload = {
      request_id: 'req_12345',
      recipient: 'alice.eth',
      amount: 100,
      idempotency_key: 'idem_12345',
      verdict_token: 'token_123',
      memo: 'x'.repeat(5000),
    };
    const res = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: giantPayload,
    });
    expect(res.statusCode).toBe(413);
    expect(res.json()?.error).toContain('4KB limit');
  });

  it('Rejects request missing verdict_token with HTTP 403', async () => {
    const res = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: 'req_valid_001',
        recipient: 'alice.eth',
        amount: 100,
        idempotency_key: 'idem_no_token_001',
        // verdict_token omitted
      },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json()?.error).toContain('Missing server verdict authorization token');
  });

  it('Rejects forged verdict token with HTTP 400 GATE_REJECTION', async () => {
    const res = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: 'req_test_forged',
        recipient: 'alice.eth',
        amount: 100,
        idempotency_key: 'idem_forged_001',
        verdict_token: 'bk_auth.eyJmYWtlIjoidG9rZW4ifQ.badsignature12345',
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()?.error).toContain('GATE_REJECTION');
  });

  it('Rejects expired verdict token with HTTP 400', async () => {
    // Mint a token with an expiration in the past
    const key = getSigningKey();
    const expiredPayload = {
      rid: 'req_expired_test',
      rec: 'alice.eth',
      amt: 100,
      memo: 'test',
      v: 'APPROVED' as const,
      intent: 'TRANSFER' as const,
      iat: Date.now() - 10 * 60 * 1000,
      exp: Date.now() - 1000, // expired 1s ago
    };
    const b64 = Buffer.from(JSON.stringify(expiredPayload)).toString('base64url');
    const sig = crypto.createHmac('sha256', key).update(b64).digest('hex');
    const expiredToken = `bk_auth.${b64}.${sig}`;

    const res = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: 'req_expired_test',
        recipient: 'alice.eth',
        amount: 100,
        memo: 'test',
        idempotency_key: 'idem_expired_001',
        verdict_token: expiredToken,
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()?.error).toContain('expired');
  });

  it('Rejects parameter mismatch on amount, recipient, and memo', async () => {
    // 1. Obtain authentic token via /api/analyze handler
    const analyzeRes = await invokeHandler(analyzeHandler, {
      method: 'POST',
      body: {
        raw_input: 'Transfer $100 to alice.eth for lunch',
        recipient: 'alice.eth',
        amount: 100,
        memo: 'lunch',
      },
    });
    const { verdict, verdict_token } = analyzeRes.json();
    expect(verdict_token).toBeDefined();

    // 2. Tamper Amount ($100 -> $999)
    const amountTamperRes = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: verdict.request_id,
        recipient: 'alice.eth',
        amount: 999, // tampered
        memo: 'lunch',
        idempotency_key: 'idem_amt_tamper',
        verdict_token,
      },
    });
    expect(amountTamperRes.statusCode).toBe(400);
    expect(amountTamperRes.json()?.error).toContain('Token amount');

    // 3. Tamper Recipient (alice.eth -> bob_miller)
    const recipTamperRes = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: verdict.request_id,
        recipient: 'bob_miller', // tampered
        amount: 100,
        memo: 'lunch',
        idempotency_key: 'idem_recip_tamper',
        verdict_token,
      },
    });
    expect(recipTamperRes.statusCode).toBe(400);
    expect(recipTamperRes.json()?.error).toContain('Token recipient');

    // 4. Tamper Memo (lunch -> unauthorized wire)
    const memoTamperRes = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: verdict.request_id,
        recipient: 'alice.eth',
        amount: 100,
        memo: 'unauthorized wire', // tampered
        idempotency_key: 'idem_memo_tamper',
        verdict_token,
      },
    });
    expect(memoTamperRes.statusCode).toBe(400);
    expect(memoTamperRes.json()?.error).toContain('Token memo');
  });

  it('Executes valid transfer, enforces idempotency and blocks single-use token replay', async () => {
    // 1. Analyze
    const analyzeRes = await invokeHandler(analyzeHandler, {
      method: 'POST',
      body: {
        raw_input: 'Transfer $250 to alice.eth for dinner',
        recipient: 'alice.eth',
        amount: 250,
        memo: 'dinner',
      },
    });
    const { verdict, verdict_token } = analyzeRes.json();
    const idemKey = `idem_exec_full_${Date.now()}`;

    // 2. Execute first time -> 200 OK
    const execRes1 = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: verdict.request_id,
        recipient: 'alice.eth',
        amount: 250,
        memo: 'dinner',
        idempotency_key: idemKey,
        verdict_token,
      },
    });
    expect(execRes1.statusCode).toBe(200);
    expect(execRes1.json()?.success).toBe(true);
    expect(execRes1.json()?.updated_balance).toBe(4750);

    // 3. Idempotent re-submission (same idempotency_key) -> 400 DUPLICATE_REJECTED
    const execResDup = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: verdict.request_id,
        recipient: 'alice.eth',
        amount: 250,
        memo: 'dinner',
        idempotency_key: idemKey,
        verdict_token,
      },
    });
    expect(execResDup.statusCode).toBe(400);
    expect(execResDup.json()?.error).toContain('DUPLICATE_REJECTED');
    expect(ledgerStore.getBalance()).toBe(4750); // no double-charge

    // 4. Token Replay (fresh idempotency_key but previously redeemed request_id) -> 400 REPLAY_REJECTED
    const execResReplay = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: verdict.request_id,
        recipient: 'alice.eth',
        amount: 250,
        memo: 'dinner',
        idempotency_key: `idem_replay_diff_${Date.now()}`,
        verdict_token,
      },
    });
    expect(execResReplay.statusCode).toBe(400);
    expect(execResReplay.json()?.error).toContain('REPLAY_REJECTED');
    expect(ledgerStore.getBalance()).toBe(4750);
  });

  it('/api/execute-transfer rejects expired authorization tokens with 400 GATE_REJECTION', async () => {
    const expiredPayload = {
      rid: `req_exp_${Date.now()}`,
      rec: 'alice.eth',
      amt: 100,
      memo: 'lunch',
      v: 'APPROVED',
      intent: 'TRANSFER',
      iat: Date.now() - 600000,
      exp: Date.now() - 1000, // expired 1s ago
    };
    const b64 = Buffer.from(JSON.stringify(expiredPayload)).toString('base64url');
    const sig = crypto.createHmac('sha256', getSigningKey()).update(b64).digest('hex');
    const expiredToken = `bk_auth.${b64}.${sig}`;

    const res = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: expiredPayload.rid,
        recipient: 'alice.eth',
        amount: 100,
        memo: 'lunch',
        idempotency_key: `idem_exp_${Date.now()}`,
        verdict_token: expiredToken,
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json()?.error).toContain('GATE_REJECTION: Authorization token expired');
  });

  it('/api/execute-transfer rejects tampered token signatures with 400 GATE_REJECTION', async () => {
    const payload = {
      rid: `req_tamper_${Date.now()}`,
      rec: 'alice.eth',
      amt: 100,
      memo: 'lunch',
      v: 'APPROVED',
      intent: 'TRANSFER',
      iat: Date.now(),
      exp: Date.now() + 60000,
    };
    const b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', getSigningKey()).update(b64).digest('hex');
    // Flip a character in signature
    const corruptedSig = sig.slice(0, -1) + (sig.slice(-1) === 'a' ? 'b' : 'a');
    const tamperedToken = `bk_auth.${b64}.${corruptedSig}`;

    const res = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: payload.rid,
        recipient: 'alice.eth',
        amount: 100,
        memo: 'lunch',
        idempotency_key: `idem_tamper_${Date.now()}`,
        verdict_token: tamperedToken,
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json()?.error).toContain('Invalid token signature. Forged or tampered authorization token detected.');
  });

  it('/api/execute-transfer rejects tokens containing unapproved status', async () => {
    const unapprovedPayload = {
      rid: `req_unappr_${Date.now()}`,
      rec: 'alice.eth',
      amt: 100,
      memo: 'lunch',
      v: 'BLOCKED',
      intent: 'TRANSFER',
      iat: Date.now(),
      exp: Date.now() + 60000,
    };
    const b64 = Buffer.from(JSON.stringify(unapprovedPayload)).toString('base64url');
    const sig = crypto.createHmac('sha256', getSigningKey()).update(b64).digest('hex');
    const unapprovedToken = `bk_auth.${b64}.${sig}`;

    const res = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: {
        request_id: unapprovedPayload.rid,
        recipient: 'alice.eth',
        amount: 100,
        memo: 'lunch',
        idempotency_key: `idem_unappr_${Date.now()}`,
        verdict_token: unapprovedToken,
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json()?.error).toContain('Token does not contain an approved transfer authorization.');
  });

  it('Enforces balance invariants and fail-closed rejections under concurrent transfer load', async () => {
    ledgerStore.resetLedger();

    // Generate 6 distinct approved tokens for $1,000 each (starting balance $5,000)
    const requests = await Promise.all(
      Array.from({ length: 6 }).map(async (_, idx) => {
        const analyzeRes = await invokeHandler(analyzeHandler, {
          method: 'POST',
          body: {
            raw_input: `Transfer $1000 to alice.eth payment ${idx}`,
            recipient: 'alice.eth',
            amount: 1000,
            memo: `payment ${idx}`,
          },
        });
        const { verdict, verdict_token } = analyzeRes.json();
        return {
          request_id: verdict.request_id,
          recipient: 'alice.eth',
          amount: 1000,
          memo: `payment ${idx}`,
          idempotency_key: `idem_concurrent_race_${idx}_${Date.now()}`,
          verdict_token,
        };
      })
    );

    // Dispatch all 6 execution requests concurrently
    const executionResults = await Promise.all(
      requests.map((reqPayload) =>
        invokeHandler(executeTransferHandler, {
          method: 'POST',
          body: reqPayload,
        })
      )
    );

    const succeeded = executionResults.filter((r) => r.statusCode === 200 && r.json()?.success === true);
    const failed = executionResults.filter((r) => r.statusCode === 400 && r.json()?.success === false);

    expect(succeeded.length).toBe(5);
    expect(failed.length).toBe(1);
    expect(failed[0].json()?.error).toContain('Insufficient demo funds');
    expect(ledgerStore.getBalance()).toBe(0);
  });

  it('Enforces single execution when identical idempotency keys race concurrently', async () => {
    ledgerStore.resetLedger();

    const analyzeRes = await invokeHandler(analyzeHandler, {
      method: 'POST',
      body: {
        raw_input: 'Transfer $500 to bob_miller for consulting',
        recipient: 'bob_miller',
        amount: 500,
        memo: 'consulting',
      },
    });
    const { verdict, verdict_token } = analyzeRes.json();
    const sharedIdemKey = `idem_race_duplicate_${Date.now()}`;

    // Dispatch 4 simultaneous calls with identical idempotency key
    const raceResults = await Promise.all(
      Array.from({ length: 4 }).map(() =>
        invokeHandler(executeTransferHandler, {
          method: 'POST',
          body: {
            request_id: verdict.request_id,
            recipient: 'bob_miller',
            amount: 500,
            memo: 'consulting',
            idempotency_key: sharedIdemKey,
            verdict_token,
          },
        })
      )
    );

    const succeeded = raceResults.filter((r) => r.statusCode === 200 && r.json()?.success === true);
    const duplicates = raceResults.filter((r) => r.statusCode === 400 && r.json()?.error?.includes('DUPLICATE_REJECTED'));

    expect(succeeded.length).toBe(1);
    expect(duplicates.length).toBe(3);
    expect(ledgerStore.getBalance()).toBe(4500);
  });
});

// ─── SUITE 3: /api/ledger Handler & ADMIN_RESET_TOKEN Tests ─────────────────

describe('HTTP Handler Integration — /api/ledger', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    ledgerStore.resetLedger();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('GET /api/ledger returns current balance, transactions, and storage info', async () => {
    const res = await invokeHandler(ledgerHandler, { method: 'GET' });
    expect(res.statusCode).toBe(200);
    const data = res.json();
    expect(data?.balance).toBe(5000);
    expect(Array.isArray(data?.transactions)).toBe(true);
    expect(data?.storage_info?.type).toBe('LOCAL_IN_MEMORY_DEMO');
    expect(data?.storage_info?.multiInstanceConsistent).toBe(false);
  });

  it('Allows reset in development mode without admin token', async () => {
    delete process.env.NODE_ENV;
    delete process.env.ADMIN_RESET_TOKEN;

    const res = await invokeHandler(ledgerHandler, {
      method: 'POST',
      body: { action: 'reset' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()?.balance).toBe(5000);
  });

  it('In production mode: rejects reset if ADMIN_RESET_TOKEN is not configured', async () => {
    process.env.NODE_ENV = 'production';
    delete process.env.ADMIN_RESET_TOKEN;

    const res = await invokeHandler(ledgerHandler, {
      method: 'POST',
      body: { action: 'reset' },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json()?.error).toContain('FORBIDDEN');
    expect(res.json()?.error).toContain('no ADMIN_RESET_TOKEN is configured');
  });

  it('In production mode: rejects reset with incorrect token (timing-safe)', async () => {
    process.env.NODE_ENV = 'production';
    process.env.ADMIN_RESET_TOKEN = 'secret_admin_token_bankism_12345';

    const res = await invokeHandler(ledgerHandler, {
      method: 'POST',
      headers: { 'x-admin-token': 'wrong_secret_token_abc' },
      body: { action: 'reset' },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json()?.error).toContain('Invalid or missing administrator reset token');
  });

  it('In production mode: permits reset with valid x-admin-token header', async () => {
    process.env.NODE_ENV = 'production';
    const secret = 'secret_admin_token_bankism_12345';
    process.env.ADMIN_RESET_TOKEN = secret;

    const res = await invokeHandler(ledgerHandler, {
      method: 'POST',
      headers: { 'x-admin-token': secret },
      body: { action: 'reset' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()?.balance).toBe(5000);
  });
});

// ─── SUITE 4: Missing Signing Key in Production Mode ────────────────────────

describe('HTTP Handler Integration — Missing FIREWALL_SIGNING_KEY in Production', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('/api/analyze fails closed and halts token issuance when key missing in production', async () => {
    process.env.NODE_ENV = 'production';
    delete process.env.FIREWALL_SIGNING_KEY;

    const res = await invokeHandler(analyzeHandler, {
      method: 'POST',
      body: {
        raw_input: 'Transfer $100 to alice.eth',
        recipient: 'alice.eth',
        amount: 100,
      },
    });

    // When signing throws in production, catch block returns fail-closed verdict
    expect(res.statusCode).toBe(200);
    const data = res.json();
    expect(data?.verdict?.verdict).toBe('BLOCKED');
    expect(data?.verdict?.engine_mode).toBe('FAIL_CLOSED');
    expect(data?.verdict_token).toBeUndefined();
  });

  it('/api/analyze fails closed if FIREWALL_SIGNING_KEY is the dev fallback key in production', async () => {
    process.env.NODE_ENV = 'production';
    process.env.FIREWALL_SIGNING_KEY = 'bankism_dev_only_ephemeral_signing_key_soc_2026_min_32_chars';

    const res = await invokeHandler(analyzeHandler, {
      method: 'POST',
      body: {
        raw_input: 'Transfer $100 to alice.eth',
        recipient: 'alice.eth',
        amount: 100,
      },
    });

    expect(res.statusCode).toBe(200);
    const data = res.json();
    expect(data?.verdict?.verdict).toBe('BLOCKED');
    expect(data?.verdict?.engine_mode).toBe('FAIL_CLOSED');
    expect(data?.verdict_token).toBeUndefined();
  });

  it('/api/analyze fails closed if FIREWALL_SIGNING_KEY is shorter than 32 characters in production', async () => {
    process.env.NODE_ENV = 'production';
    process.env.FIREWALL_SIGNING_KEY = 'short_key_123';

    const res = await invokeHandler(analyzeHandler, {
      method: 'POST',
      body: {
        raw_input: 'Transfer $100 to alice.eth',
        recipient: 'alice.eth',
        amount: 100,
      },
    });

    expect(res.statusCode).toBe(200);
    const data = res.json();
    expect(data?.verdict?.verdict).toBe('BLOCKED');
    expect(data?.verdict?.engine_mode).toBe('FAIL_CLOSED');
    expect(data?.verdict_token).toBeUndefined();
  });
});

// ─── SUITE 5: Malformed JSON, Array Bodies & Body Admin Reset ───────────────

describe('HTTP Handler Integration — Body Edge Cases & Admin Auth', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('/api/execute-transfer rejects malformed streaming JSON with 400 GATE_REJECTION', async () => {
    const res = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: '{"invalid": json_stream_content, missing_quotes}',
      stream: true,
    });

    expect(res.statusCode).toBe(400);
    expect(res.json()?.error).toContain('GATE_REJECTION: Malformed JSON request body.');
  });

  it('/api/execute-transfer rejects array request body with 400 GATE_REJECTION', async () => {
    const res = await invokeHandler(executeTransferHandler, {
      method: 'POST',
      body: [{ amount: 100, recipient: 'alice.eth' }],
    });

    expect(res.statusCode).toBe(400);
    expect(res.json()?.error).toContain('GATE_REJECTION: Malformed request body object.');
  });

  it('/api/analyze rejects array request body with fail-closed BLOCKED verdict', async () => {
    const res = await invokeHandler(analyzeHandler, {
      method: 'POST',
      body: [{ raw_input: 'Transfer $100 to alice.eth' }],
    });

    expect(res.statusCode).toBe(200);
    const data = res.json();
    expect(data?.verdict?.verdict).toBe('BLOCKED');
    expect(data?.verdict?.engine_mode).toBe('FAIL_CLOSED');
    expect(data?.verdict_token).toBeUndefined();
  });

  it('/api/ledger permits reset in production using body.admin_token', async () => {
    process.env.NODE_ENV = 'production';
    const secret = 'prod_secret_token_body_admin_12345';
    process.env.ADMIN_RESET_TOKEN = secret;

    const res = await invokeHandler(ledgerHandler, {
      method: 'POST',
      body: {
        action: 'reset',
        admin_token: secret,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()?.balance).toBe(5000);
  });

  it('/api/ledger rejects reset in production with incorrect body.admin_token', async () => {
    process.env.NODE_ENV = 'production';
    const secret = 'prod_secret_token_body_admin_12345';
    process.env.ADMIN_RESET_TOKEN = secret;

    const res = await invokeHandler(ledgerHandler, {
      method: 'POST',
      body: {
        action: 'reset',
        admin_token: 'incorrect_body_token_xyz',
      },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json()?.error).toContain('Invalid or missing administrator reset token');
  });
});
