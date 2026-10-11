/**
 * Serverless API Route: /api/ledger
 * Read-only or protected reset endpoint for the sandbox mock ledger.
 * Public reset is strictly disabled in production unless an administrator secret is configured.
 */

import crypto from 'node:crypto';
import { ledgerStore } from '../src/security/transactionGate';

const MAX_PAYLOAD_BYTES = 1024;

export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-admin-token');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  if (req.method === 'POST') {
    let body: any = req.body;
    if (typeof body === 'object' && body !== null) {
      if (Buffer.byteLength(JSON.stringify(body)) > MAX_PAYLOAD_BYTES) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large.' }));
        return;
      }
    } else {
      const buffers: any[] = [];
      let total = 0;
      await new Promise<void>((resolve) => {
        req.on('data', (c: any) => {
          total += c.length;
          if (total <= MAX_PAYLOAD_BYTES) buffers.push(c);
        });
        req.on('end', () => {
          try {
            const raw = Buffer.concat(buffers).toString('utf-8');
            body = raw ? JSON.parse(raw) : {};
          } catch {
            body = {};
          }
          resolve();
        });
      });
    }

    if (body?.action === 'reset') {
      const isProduction = process.env.NODE_ENV === 'production';
      const adminSecret = process.env.ADMIN_RESET_TOKEN;

      if (isProduction) {
        // In production, public reset is disabled unless a secret is configured and verified
        if (!adminSecret) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'FORBIDDEN: Public ledger reset is disabled in production and no ADMIN_RESET_TOKEN is configured.' }));
          return;
        }

        const providedToken = String(req.headers['x-admin-token'] || body?.admin_token || '');
        const providedBuf = Buffer.from(providedToken, 'utf-8');
        const expectedBuf = Buffer.from(adminSecret, 'utf-8');

        if (providedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(providedBuf, expectedBuf)) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'FORBIDDEN: Invalid or missing administrator reset token.' }));
          return;
        }
      }

      // Reset allowed in dev/test or with valid admin secret
      ledgerStore.resetLedger();
    }
  }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      balance: ledgerStore.getBalance(),
      transactions: ledgerStore.getTransactions(),
      storage_info: ledgerStore.getStorageInfo(),
    })
  );
}
