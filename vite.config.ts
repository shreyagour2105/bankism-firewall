import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import analyzeHandler from './api/analyze';
import executeHandler from './api/execute-transfer';
import ledgerHandler from './api/ledger';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    {
      name: 'api-server-middleware',
      configureServer(server) {
        server.middlewares.use(async (req, res, next) => {
          const url = req.url?.split('?')[0];
          try {
            if (url === '/api/analyze') {
              await analyzeHandler(req, res);
            } else if (url === '/api/execute-transfer') {
              await executeHandler(req, res);
            } else if (url === '/api/ledger') {
              await ledgerHandler(req, res);
            } else {
              next();
            }
          } catch (err) {
            console.error('API middleware error:', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Internal server error in dev API proxy' }));
          }
        });
      },
    },
  ],
  // @ts-expect-error vitest config
  test: {
    globals: true,
    environment: 'node',
  },
});
