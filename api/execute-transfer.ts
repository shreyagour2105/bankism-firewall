/**
 * Serverless API Route: /api/execute-transfer
 * Deterministic authorization gate for executing authorized mock banking transfers.
 * Validates cryptographic HMAC token, enforces atomic idempotency, and prevents replay attacks.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { ledgerStore } from '../src/security/transactionGate';
import { ExecuteTransferPayload } from '../src/types/firewall';

export type ApiRequest = IncomingMessage & { body?: any };
export type ApiResponse = ServerResponse;

const MAX_PAYLOAD_BYTES = 4096;

export default async function handler(req: ApiRequest, res: ApiResponse) {
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

    // 1. Enforce payload size limits for both parsed and streaming bodies
    if (typeof body === 'object' && body !== null) {
      const size = Buffer.byteLength(JSON.stringify(body));
      if (size > MAX_PAYLOAD_BYTES) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'GATE_REJECTION: Request payload exceeds 4KB limit.' }));
        return;
      }
    } else {
      const buffers: any[] = [];
      let totalSize = 0;
      await new Promise<void>((resolve, reject) => {
        req.on('data', (chunk: any) => {
          totalSize += chunk.length;
          if (totalSize > MAX_PAYLOAD_BYTES) {
            reject(new Error('PAYLOAD_TOO_LARGE'));
          }
          buffers.push(chunk);
        });
        req.on('end', () => {
          try {
            const raw = Buffer.concat(buffers).toString('utf-8');
            body = raw ? JSON.parse(raw) : {};
            resolve();
          } catch {
            reject(new Error('INVALID_JSON'));
          }
        });
      });
    }

    // 2. Strict Input Schema Validation
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'GATE_REJECTION: Malformed request body object.' }));
      return;
    }

    const requestId = typeof body.request_id === 'string' ? body.request_id.trim() : '';
    const recipient = typeof body.recipient === 'string' ? body.recipient.trim() : '';
    const amount = typeof body.amount === 'number' ? body.amount : Number(body.amount);
    const idempotencyKey = typeof body.idempotency_key === 'string' ? body.idempotency_key.trim() : '';
    const verdictToken = typeof body.verdict_token === 'string' ? body.verdict_token.trim() : '';
    const memo = typeof body.memo === 'string' ? body.memo.trim().slice(0, 255) : undefined;

    if (!requestId || requestId.length < 5 || requestId.length > 100) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'GATE_REJECTION: Invalid or missing request_id.' }));
      return;
    }

    if (!recipient || recipient.length < 1 || recipient.length > 100) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'GATE_REJECTION: Invalid or missing recipient.' }));
      return;
    }

    if (!Number.isFinite(amount) || isNaN(amount) || amount <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'GATE_REJECTION: Amount must be a positive finite number.' }));
      return;
    }

    if (!idempotencyKey || idempotencyKey.length < 5 || idempotencyKey.length > 100) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'GATE_REJECTION: Invalid or missing idempotency_key.' }));
      return;
    }

    if (!verdictToken) {
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

    const payload: ExecuteTransferPayload = {
      request_id: requestId,
      recipient,
      amount,
      memo,
      idempotency_key: idempotencyKey,
      verdict_token: verdictToken,
    };

    const result = ledgerStore.executeTransfer(payload);

    res.writeHead(result.success ? 200 : 400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  } catch (err: any) {
    if (err?.message === 'INVALID_JSON') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          success: false,
          error: 'GATE_REJECTION: Malformed JSON request body.',
          updated_balance: ledgerStore.getBalance(),
        })
      );
      return;
    }
    if (err?.message === 'PAYLOAD_TOO_LARGE') {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          success: false,
          error: 'GATE_REJECTION: Request payload exceeds maximum allowable limit.',
          updated_balance: ledgerStore.getBalance(),
        })
      );
      return;
    }
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        success: false,
        error: 'GATE_REJECTION: Internal authorization gate failure. Privileged execution halted.',
        updated_balance: ledgerStore.getBalance(),
      })
    );
  }
}
