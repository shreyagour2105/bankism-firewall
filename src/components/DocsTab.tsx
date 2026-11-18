import { useState } from 'react';
import { ArrowUpRight, Check, Code2, Copy, FileText, ShieldCheck } from 'lucide-react';
import { REPOSITORY_URL } from './Navbar';

const toolExample = `{
  "raw_input": "Transfer $150 to alice.eth for dinner",
  "tool_call": {
    "name": "transfer_funds",
    "arguments": {
      "recipient": "alice.eth",
      "amount": 150,
      "memo": "Dinner"
    }
  }
}`;

const confirmExample = `{
  "action": "confirm",
  "consent": true,
  "request_id": "<verdict.request_id>",
  "recipient": "alice.eth",
  "amount": 150,
  "memo": "Dinner",
  "idempotency_key": "<stable transaction key>",
  "verdict_token": "<token from analysis>"
}`;

export function DocsTab() {
  const [clipboard, setClipboard] = useState<{ example: string; success: boolean }>();

  async function copy(example: string, id: string) {
    try {
      await navigator.clipboard.writeText(example);
      setClipboard({ example: id, success: true });
    } catch {
      setClipboard({ example: id, success: false });
    }
  }

  function copyButton(example: string, id: string) {
    const copied = clipboard?.example === id && clipboard.success;
    return <button type="button" className="small-button inline-flex items-center gap-2" onClick={() => copy(example, id)}>
      {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
      {copied ? 'Copied' : 'Copy JSON'}
    </button>;
  }

  return (
    <section className="workspace-view">
      <div className="workspace-heading">
        <h1>API documentation</h1>
        <p>Request formats, policy verdicts, and the mock transfer flow.</p>
      </div>
      {clipboard && !clipboard.success && <p role="status" className="text-sm text-amber-200 mb-3">Clipboard unavailable. Select the JSON to copy it.</p>}
      <div className="docs-layout">
        <article className="docs-panel">
          <header><h2><Code2 size={17} aria-hidden="true" /> Analyze a request</h2>{copyButton(toolExample, 'analysis')}</header>
          <p><code>POST /api/analyze</code></p>
          <p>Send a banking prompt in <code>raw_input</code> with optional transfer fields, or send one <code>tool_call</code> with optional <code>raw_input</code> for comparison. The request body limit is 4 KB.</p>
          <pre>{toolExample}</pre>
          <ul>
            <li><code>get_balance</code> and <code>list_transactions</code> accept an empty <code>arguments</code> object.</li>
            <li><code>transfer_funds</code> accepts <code>recipient</code>, numeric USD <code>amount</code> with up to two decimal places, and optional <code>memo</code>.</li>
            <li>Set <code>simulate</code> to <code>true</code> to get a deterministic verdict without minting a transfer review token.</li>
          </ul>
        </article>
        <article className="docs-panel">
          <header><h2><ShieldCheck size={17} aria-hidden="true" /> Confirm and execute</h2>{copyButton(confirmExample, 'confirmation')}</header>
          <p><code>POST /api/execute-transfer</code></p>
          <ol>
            <li>Show the amount, recipient and memo from <code>extracted_parameters</code> when the verdict requires confirmation.</li>
            <li>After explicit approval, use the <code>confirm</code> action to get a signed <code>consent_token</code>.</li>
            <li>Send the same request ID, exact details, idempotency key and verdict token with the consent token. Omit <code>action</code> and <code>consent</code> to execute the mock transfer.</li>
          </ol>
          <pre>{confirmExample}</pre>
          <p>The confirmation expires within 60 seconds. This public prototype has no user identity verification. Replay protection and ledger state are scoped to one running server process.</p>
        </article>
        <article className="docs-panel">
          <h2><FileText size={17} aria-hidden="true" /> Read the verdict</h2>
          <p><code>APPROVED</code>, <code>BLOCKED</code>, and <code>REVIEW_REQUIRED</code> indicate the policy decision. Each verdict includes the request ID, intent, risk, threat categories, rationale and individual policy checks.</p>
          <p>Structured calls include <code>request_source</code> and, for a valid schema, <code>tool_name</code>. View the full response under <strong>Structured JSON verdict</strong> in the console.</p>
        </article>
        <article className="docs-panel">
          <h2>Mock ledger and local setup</h2>
          <p><code>GET /api/ledger</code> returns the current process’s mock balance, transaction history, and storage scope. Reset is available locally and requires an administrator secret in production.</p>
          <p>Run <code>npm ci</code>, <code>npm run dev</code>, <code>npm test</code>, and <code>npm run build</code> in the existing repository.</p>
          <a className="text-link mt-3" href={REPOSITORY_URL}>View source and configuration <ArrowUpRight size={15} aria-hidden="true" /></a>
        </article>
      </div>
    </section>
  );
}
