/**
 * Serverless API Route: /api/execute-transfer
 * Deterministic authorization gate for executing authorized mock banking transfers.
 * Rejects unverified tokens, duplicate idempotency keys, and tampered requests.
 */

import { ledgerStore } from '../src/security/transactionGate';
import { ExecuteTransferPayload } from '../src/types/firewall';

export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method Not Allowed' }));
    return;
  }

  try {
    let body: any = req.body;
    if (!body || typeof body === 'string') {
      const buffers: any[] = [];
      await new Promise<void>((resolve, reject) => {
        req.on('data', (chunk: any) => buffers.push(chunk));
        req.on('end', () => {
          try {
            const raw = Buffer.concat(buffers).toString();
            body = raw ? JSON.parse(raw) : {};
            resolve();
          } catch (e) {
            reject(new Error('INVALID_JSON'));
          }
        });
      });
    }

    const payload: ExecuteTransferPayload = {
      request_id: String(body?.request_id || ''),
      recipient: String(body?.recipient || ''),
      amount: Number(body?.amount || 0),
      memo: body?.memo ? String(body.memo) : undefined,
      idempotency_key: String(body?.idempotency_key || ''),
      verdict_token: String(body?.verdict_token || ''),
    };

    if (!payload.verdict_token) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          success: false,
          error: 'SECURITY GATE ERROR: Missing server verdict authorization token.',
          updated_balance: ledgerStore.getBalance(),
        })
      );
      return;
    }

    const result = ledgerStore.executeTransfer(payload);

    res.writeHead(result.success ? 200 : 400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  } catch (err: any) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        success: false,
        error: `Server-side transaction gate exception: ${err.message}`,
        updated_balance: ledgerStore.getBalance(),
      })
    );
  }
}
