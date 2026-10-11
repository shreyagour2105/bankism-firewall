/**
 * Serverless API Route: /api/ledger
 * Read-only or reset endpoint for the sandbox mock ledger
 */

import { ledgerStore } from '../src/security/transactionGate';

export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  if (req.method === 'POST') {
    // Check if reset action
    let body: any = req.body;
    if (!body || typeof body === 'string') {
      const buffers: any[] = [];
      await new Promise<void>((resolve) => {
        req.on('data', (c: any) => buffers.push(c));
        req.on('end', () => {
          try {
            const raw = Buffer.concat(buffers).toString();
            body = raw ? JSON.parse(raw) : {};
          } catch {
            body = {};
          }
          resolve();
        });
      });
    }

    if (body?.action === 'reset') {
      ledgerStore.resetLedger();
    }
  }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      balance: ledgerStore.getBalance(),
      transactions: ledgerStore.getTransactions(),
    })
  );
}
