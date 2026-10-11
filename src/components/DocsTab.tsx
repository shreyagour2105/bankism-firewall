import React, { useState } from 'react';
import {
  FileText,
  Code,
  Terminal,
  Cloud,
  Copy,
  Check,
  Key,
  ShieldCheck,
} from 'lucide-react';

export const DocsTab: React.FC = () => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const schemaExample = `{
  "request_id": "req_bkm_m7q8x_91a02",
  "timestamp": "2026-10-11T05:15:30.123Z",
  "verdict": "APPROVED | BLOCKED | REVIEW_REQUIRED",
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "threat_category": [
    "NONE",
    "PROMPT_INJECTION",
    "JAILBREAK",
    "POLICY_OVERRIDE",
    "MALICIOUS_MEMO",
    "OBFUSCATION",
    "DATA_EXFILTRATION",
    "AMBIGUOUS_REQUEST",
    "INVALID_TRANSACTION",
    "ANALYSIS_FAILURE"
  ],
  "intent": "BALANCE_INQUIRY | TRANSFER | OTHER | UNKNOWN",
  "rationale": "Human-readable explanation of why the firewall made this decision",
  "normalised_request": "Sanitised and deobfuscated representation",
  "extracted_parameters": {
    "recipient": "alice.eth",
    "amount": 150.00,
    "memo": "dinner expenses"
  },
  "requires_confirmation": true,
  "transaction_executed": false,
  "checks": {
    "schema_valid": true,
    "input_normalised": true,
    "threat_scan_passed": true,
    "policy_passed": true,
    "recipient_valid": true,
    "amount_valid": true
  },
  "engine_mode": "DETERMINISTIC_RULES | HYBRID_LLM_ADVISORY | FAIL_CLOSED",
  "latency_ms": 12
}`;

  const curlAnalyzeExample = `curl -X POST https://your-bankism-deploy.vercel.app/api/analyze \\
  -H "Content-Type: application/json" \\
  -d '{
    "raw_input": "Transfer $150 to alice.eth for dinner expenses",
    "recipient": "alice.eth",
    "amount": 150.00,
    "memo": "dinner expenses"
  }'`;

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="p-5 rounded-xl bg-[#0f172a] border border-slate-800">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-cyan-400" />
          <h2 className="text-xl font-bold font-mono text-white">Developer Guide &amp; Technical Documentation</h2>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Complete schema specifications, automated testing guide, API endpoints, and deployment instructions.
        </p>
      </div>

      {/* Structured Verdict Schema */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
            <Code className="w-4 h-4 text-cyan-400" />
            Strict JSON Verdict Schema
          </h3>
          <button
            onClick={() => copyToClipboard(schemaExample, 'schema')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 flex items-center gap-1"
          >
            {copiedKey === 'schema' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedKey === 'schema' ? 'Copied' : 'Copy Schema'}</span>
          </button>
        </div>
        <p className="text-xs text-slate-400 mb-3">
          Every request analyzed by Bankism returns a deterministic, machine-readable verdict with strict schema validation.
        </p>
        <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto leading-relaxed">
          {schemaExample}
        </pre>
      </div>

      {/* API Reference & cURL */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              1. Intercept &amp; Analyze Endpoint
            </h3>
            <button
              onClick={() => copyToClipboard(curlAnalyzeExample, 'curl1')}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 flex items-center gap-1"
            >
              {copiedKey === 'curl1' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedKey === 'curl1' ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="text-xs font-mono text-cyan-400 mb-2">POST /api/analyze</div>
          <p className="text-xs text-slate-400 mb-3">
            Payload size limit: 4KB. Returns structured JSON verdict and optional single-use authorization token.
          </p>
          <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
            {curlAnalyzeExample}
          </pre>
        </div>

        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              2. Authorized Transaction Gate
            </h3>
          </div>
          <div className="text-xs font-mono text-emerald-400 mb-2">POST /api/execute-transfer</div>
          <p className="text-xs text-slate-400 mb-3">
            Requires <code className="text-cyan-300">verdict_token</code> and <code className="text-cyan-300">idempotency_key</code>. Rejects forged client states or duplicate replays.
          </p>
          <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
{`curl -X POST /api/execute-transfer \\
  -H "Content-Type: application/json" \\
  -d '{
    "request_id": "req_...",
    "recipient": "alice.eth",
    "amount": 150.00,
    "idempotency_key": "idem_...",
    "verdict_token": "bk_auth_tok_..."
  }'`}
          </pre>
        </div>
      </div>

      {/* Testing & Configuration Guide */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold font-mono text-slate-200 mb-2 flex items-center gap-2">
            <Key className="w-4 h-4 text-amber-400" />
            Configuring Optional LLM Provider
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed mb-3">
            Bankism runs 100% out of the box in <strong>Deterministic Mode</strong> without requiring any paid API keys.
            To optionally enable advisory AI analysis, add your key to a server-side <code className="text-white">.env</code> file:
          </p>
          <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 mb-3">
            GEMINI_API_KEY=your_key_here
          </pre>
          <div className="text-[11px] text-amber-400/90 font-mono">
            * Security guarantee: API keys remain exclusively on the server and are never bundled in client code.
          </div>
        </div>

        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold font-mono text-slate-200 mb-2 flex items-center gap-2">
            <Cloud className="w-4 h-4 text-cyan-400" />
            Running Tests &amp; Deploying to Vercel
          </h3>
          <div className="space-y-2 text-xs font-mono">
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500"># Run Vitest automated test suite</span>
              <div className="text-cyan-300">npm test</div>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500"># Build TypeScript and production bundle</span>
              <div className="text-cyan-300">npm run build</div>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500"># Deploy to Vercel Serverless</span>
              <div className="text-cyan-300">vercel --prod</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
