import { useState } from 'react';
import { ArrowRight, Code2, TextCursorInput } from 'lucide-react';
import { SIMULATION_CASES } from '../data/simulationCases';
import type { FirewallVerdict, AnalyzeRequestPayload } from '../types/firewall';
import { VerdictPanel } from './VerdictPanel';

interface ConsoleTabProps {
  onAnalyze: (payload: AnalyzeRequestPayload) => Promise<unknown>;
  onExecuteTransfer: (verdict: FirewallVerdict, token: string) => Promise<void>;
  verdict: FirewallVerdict | null;
  verdictToken?: string;
  isAnalyzing: boolean;
  isExecuting: boolean;
  executionResult: { success: boolean; message: string; txId?: string } | null;
  initialPayload?: AnalyzeRequestPayload;
}

const EXAMPLE_TOOL = JSON.stringify({
  name: 'transfer_funds',
  arguments: { recipient: 'alice.eth', amount: 150, memo: 'Dinner expenses' },
}, null, 2);

export function ConsoleTab({
  onAnalyze, onExecuteTransfer, verdict, verdictToken, isAnalyzing, isExecuting,
  executionResult, initialPayload,
}: ConsoleTabProps) {
  const [mode, setMode] = useState<'prompt' | 'tool'>(initialPayload?.tool_call !== undefined ? 'tool' : 'prompt');
  const [rawInput, setRawInput] = useState(initialPayload?.raw_input ?? '');
  const [toolJson, setToolJson] = useState(
    initialPayload?.tool_call !== undefined ? JSON.stringify(initialPayload.tool_call, null, 2) : EXAMPLE_TOOL
  );
  const [recipient, setRecipient] = useState(initialPayload?.recipient ?? '');
  const [amount, setAmount] = useState(initialPayload?.amount?.toString() ?? '');
  const [memo, setMemo] = useState(initialPayload?.memo ?? '');
  const [showAdvanced, setShowAdvanced] = useState(Boolean(recipient || amount || memo));
  const [error, setError] = useState('');

  function loadExample(payload: AnalyzeRequestPayload) {
    setRawInput(payload.raw_input);
    setRecipient(payload.recipient ?? '');
    setAmount(payload.amount?.toString() ?? '');
    setMemo(payload.memo ?? '');
    setShowAdvanced(Boolean(payload.recipient || payload.amount !== undefined || payload.memo));
    setMode(payload.tool_call === undefined ? 'prompt' : 'tool');
    if (payload.tool_call !== undefined) setToolJson(JSON.stringify(payload.tool_call, null, 2));
    setError('');
  }

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (isAnalyzing || isExecuting) return;
    setError('');
    const payload: AnalyzeRequestPayload = { raw_input: rawInput.trim() };
    if (mode === 'tool') {
      try {
        payload.tool_call = JSON.parse(toolJson);
      } catch {
        setError('Enter valid JSON for the proposed tool call.');
        return;
      }
    } else {
      payload.recipient = recipient.trim() || undefined;
      payload.amount = amount === '' ? undefined : Number(amount);
      payload.memo = memo.trim() || undefined;
    }
    await onAnalyze(payload);
  }

  return (
    <div className="workspace-view">
      <div className="workspace-heading">
        <h1>Analysis console</h1>
        <p>Inspect a banking prompt or validate a proposed agent tool call.</p>
      </div>
      <div className="console-grid">
        <form className="console-form" onSubmit={submit}>
          <fieldset>
            <legend className="sr-only">Request format</legend>
            <div className="segmented">
              <label><input type="radio" name="request-mode" checked={mode === 'prompt'} onChange={() => { setMode('prompt'); setError(''); }} /><TextCursorInput size={15} /> Banking prompt</label>
              <label><input type="radio" name="request-mode" checked={mode === 'tool'} onChange={() => { setMode('tool'); setError(''); }} /><Code2 size={16} /> Agent tool call</label>
            </div>
          </fieldset>
          <div>
            <label className="field-label" htmlFor="request-example">Load an example</label>
            <select id="request-example" value="" onChange={(event) => {
              const example = SIMULATION_CASES.find(({ id }) => id === event.target.value);
              if (example) loadExample(example.payload);
            }}>
              <option value="">Choose a lab case</option>
              {SIMULATION_CASES.map(({ id, title }) => <option key={id} value={id}>{title}</option>)}
            </select>
          </div>
          {mode === 'tool' && (
            <div>
              <label className="field-label" htmlFor="tool-json">Tool call JSON</label>
              <textarea id="tool-json" value={toolJson} onChange={(event) => setToolJson(event.target.value)}
                rows={9} spellCheck={false} required className="font-mono text-sm" />
              <p className="field-help">Allowed tools are <code>get_balance</code>, <code>list_transactions</code>, and <code>transfer_funds</code>.</p>
            </div>
          )}
          <div>
            <label className="field-label" htmlFor="input-raw-prompt">
              {mode === 'prompt' ? 'Banking instruction' : 'Original banking instruction (optional)'}
            </label>
            <textarea id="input-raw-prompt" value={rawInput} onChange={(event) => setRawInput(event.target.value)}
              rows={mode === 'tool' ? 2 : 5} maxLength={2000} required={mode === 'prompt'}
              placeholder="Transfer $150 to alice.eth for dinner" />
          </div>
          {mode === 'prompt' && (
            <div>
              <button type="button" className="text-button" onClick={() => setShowAdvanced(!showAdvanced)}
                aria-expanded={showAdvanced} aria-controls="prompt-parameters">
                {showAdvanced ? 'Hide' : 'Show'} optional transfer fields
              </button>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3" id="prompt-parameters" hidden={!showAdvanced}>
                <label className="field-label">Recipient<input value={recipient} onChange={(event) => setRecipient(event.target.value)} maxLength={100} /></label>
                <label className="field-label">Amount (USD)<input type="number" step="0.01" value={amount} onChange={(event) => setAmount(event.target.value)} /></label>
                <label className="field-label sm:col-span-2">Payment memo<input value={memo} onChange={(event) => setMemo(event.target.value)} maxLength={255} /></label>
              </div>
            </div>
          )}
          {error && <p role="alert" className="text-sm text-rose-300">{error}</p>}
          <div className="console-actions">
            <button type="button" className="text-button" onClick={() => {
              setRawInput('');
              setRecipient('');
              setAmount('');
              setMemo('');
              setError('');
              if (mode === 'tool') setToolJson('');
            }}>Clear fields</button>
            <button type="submit" className="pill pill-primary" disabled={isAnalyzing || isExecuting}>
              {isAnalyzing ? 'Analyzing…' : 'Analyze request'} <ArrowRight size={16} />
            </button>
          </div>
        </form>
        <VerdictPanel key={verdict?.request_id} verdict={verdict} verdictToken={verdictToken}
          onExecuteTransfer={onExecuteTransfer} isExecuting={isExecuting} executionResult={executionResult} />
      </div>
    </div>
  );
}
