import React, { useState } from 'react';
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  Code,
  UserCheck,
} from 'lucide-react';
import { FirewallVerdict } from '../types/firewall';

interface VerdictPanelProps {
  verdict: FirewallVerdict | null;
  verdictToken?: string;
  onExecuteTransfer?: (verdict: FirewallVerdict, token: string) => void;
  isExecuting?: boolean;
  executionResult?: { success: boolean; message: string; txId?: string } | null;
  initialJsonOpen?: boolean;
}

export const VerdictPanel: React.FC<VerdictPanelProps> = ({
  verdict,
  verdictToken,
  onExecuteTransfer,
  isExecuting = false,
  executionResult = null,
  initialJsonOpen = false,
}) => {
  const [consent, setConsent] = useState(false);
  const [copied, setCopied] = useState(false);
  const [isJsonOpen, setIsJsonOpen] = useState(initialJsonOpen);

  if (!verdict) {
    return (
      <div className="bg-[#13151c] border border-[#2a2d36] rounded-xl p-8 text-center text-slate-400">
        <ShieldCheck className="w-12 h-12 mx-auto mb-3 opacity-40 text-cyan-400" aria-hidden="true" focusable="false" />
        <h4 className="text-sm font-semibold text-slate-300 mb-1">Awaiting Security Evaluation</h4>
        <p className="text-xs max-w-sm mx-auto text-slate-400">
          Analyze a banking prompt or agent tool call to see the policy checks and verdict here.
        </p>
      </div>
    );
  }

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(verdict, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Verdict visual styles
  const verdictStyles = {
    APPROVED: {
      bg: 'bg-emerald-950/40 border-emerald-500/40 text-emerald-400',
      badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50',
      icon: <CheckCircle className="w-6 h-6 text-emerald-400 shrink-0" aria-hidden="true" focusable="false" />,
      title: 'APPROVED — REQUEST CLEARED',
    },
    BLOCKED: {
      bg: 'bg-rose-950/40 border-rose-500/40 text-rose-400',
      badge: 'bg-rose-500/20 text-rose-300 border-rose-500/50',
      icon: <XCircle className="w-6 h-6 text-rose-400 shrink-0" aria-hidden="true" focusable="false" />,
      title: 'BLOCKED — THREAT NEUTRALIZED',
    },
    REVIEW_REQUIRED: {
      bg: 'bg-amber-950/40 border-amber-500/40 text-amber-400',
      badge: 'bg-amber-500/20 text-amber-300 border-amber-500/50',
      icon: <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0" aria-hidden="true" focusable="false" />,
      title: 'REVIEW REQUIRED — POLICY BOUNDARY',
    },
  }[verdict.verdict];

  // Risk Level visual styles
  const riskBadgeStyles = {
    LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    CRITICAL: 'bg-rose-500/20 text-rose-400 border-rose-500/50',
  }[verdict.risk_level];
  const parameters = verdict.extracted_parameters;

  return (
    <div className="verdict-panel bg-[#13151c] border border-[#2a2d36] rounded-xl overflow-hidden">
      {/* Top Banner Verdict Header */}
      <div
        role="status"
        aria-live="polite"
        className={`p-4 sm:p-5 border-b ${verdictStyles.bg} flex flex-wrap items-center justify-between gap-3`}
      >
        <div className="flex items-center gap-3">
          {verdictStyles.icon}
          <div>
            <div className="flex flex-wrap items-center gap-2.5 sm:gap-3">
              <h3
                data-testid="verdict-title"
                className="font-semibold text-base sm:text-lg m-0"
              >
                {verdictStyles.title}
              </h3>
              <span className="sr-only">{' '}</span>
              <div
                data-testid="verdict-risk-badge"
                className={`inline-flex items-center text-[11px] font-mono px-2.5 py-0.5 rounded border uppercase font-semibold ${riskBadgeStyles}`}
              >
                RISK: {verdict.risk_level}
              </div>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Request ID: <span className="font-mono text-slate-300">{verdict.request_id}</span> • Latency:{' '}
              <span className="font-mono text-cyan-400">{verdict.latency_ms}ms</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs px-2.5 py-1 rounded bg-slate-900/80 border border-slate-700/60 font-mono text-slate-300">
            <strong className="text-white">{verdict.tool_name || verdict.intent}</strong>
          </span>
        </div>
      </div>

      <div className="p-4 sm:p-6 space-y-4">
        {/* Rationale Section */}
        <div>
          <h4 className="text-xs font-semibold text-slate-300 mb-1.5 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-cyan-400 shrink-0" aria-hidden="true" focusable="false" />
            {' '}
            <span>Decision Rationale</span>
          </h4>
          <div className="p-3.5 rounded-lg bg-slate-900/80 border border-[#2a2d36] text-sm text-slate-200 leading-relaxed font-sans">
            {verdict.rationale}
          </div>
        </div>

        {verdict.requires_confirmation && parameters && (
          <div className="consent-panel">
            <h4 className="flex items-center gap-2 text-sm font-semibold text-white">
              <UserCheck size={17} aria-hidden="true" /> Review mock transfer
            </h4>
            <dl className="consent-details">
              <div><dt>Amount (USD)</dt><dd>${parameters.amount}</dd></div>
              <div><dt>Recipient</dt><dd>{parameters.recipient}</dd></div>
              <div><dt>Memo</dt><dd>{parameters.memo || 'None'}</dd></div>
            </dl>

            {verdictToken && onExecuteTransfer && !executionResult?.success && (
              <div className="space-y-3">
                <label className="flex items-start gap-2 text-sm text-slate-200">
                  <input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)}
                    disabled={isExecuting} className="mt-1 accent-cyan-300" />
                  <span>I approve this exact transfer in the mock ledger.</span>
                </label>
                <button type="button" className="pill pill-primary" disabled={!consent || isExecuting}
                  onClick={() => onExecuteTransfer(verdict, verdictToken)}>
                  {isExecuting ? 'Confirming transfer…' : 'Confirm mock transfer'}
                  <ArrowRight size={16} aria-hidden="true" />
                </button>
              </div>
            )}
            {!verdictToken && !verdict.transaction_executed &&
              <p className="text-sm text-slate-400">Analyze this request in the console to start a fresh transfer review.</p>}

            {/* Execution Result Banner */}
            {executionResult && (
              <div
                role="status"
                aria-live="polite"
                className={`mt-3 p-2.5 rounded text-xs border ${
                  executionResult.success
                    ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                    : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                }`}
              >
                {executionResult.message}
                {executionResult.txId && (
                  <span className="block mt-1 font-mono text-[11px] text-slate-400">
                    Receipt ID: {executionResult.txId}
                  </span>
                )}
              </div>
            )}
          </div>
        )}

        {/* Threat Categories Detected */}
        <div>
          <h4 className="text-xs font-semibold text-slate-300 mb-1.5">
            Threat Categories Flagged
          </h4>
          {!Array.isArray(verdict.threat_category) || verdict.threat_category.length === 0 ? (
            <div className="flex flex-wrap gap-2">
              <span
                data-testid="threat-badge-none"
                className="text-xs px-2.5 py-1 rounded-md font-mono border bg-slate-800/60 text-slate-300 border-slate-700 inline-flex items-center gap-1.5"
              >
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" aria-hidden="true" focusable="false" />
                {' '}
                <span>NONE</span>
              </span>
            </div>
          ) : (
            <ul
              role="list"
              aria-label="Threat Categories Flagged"
              data-testid="threat-categories-list"
              className="flex flex-wrap gap-2 list-none p-0 m-0"
            >
              {verdict.threat_category.map((cat, idx) => {
                const isNone = cat === 'NONE';
                const label = isNone ? 'NONE' : cat.replace(/_/g, ' ');
                return (
                  <li key={`${cat}-${idx}`} className="inline-flex">
                    <span
                      data-testid={`threat-badge-${cat}`}
                      className={`text-xs px-2.5 py-1 rounded-md font-mono border inline-flex items-center gap-1.5 ${
                        isNone
                          ? 'bg-slate-800/60 text-slate-300 border-slate-700'
                          : 'bg-rose-500/15 text-rose-200 border-rose-500/30 font-semibold'
                      }`}
                    >
                      {isNone ? (
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" aria-hidden="true" focusable="false" />
                      ) : (
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0" aria-hidden="true" focusable="false" />
                      )}
                      {' '}
                      <span>{label}</span>
                    </span>
                    {' '}
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        {/* Individual Policy Checks Grid */}
        <div>
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Deterministic Security Checks
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
            {Object.entries(verdict.checks).map(([checkKey, passed]) => {
              const label = checkKey
                .replace(/_/g, ' ')
                .replace(/\b\w/g, (c) => c.toUpperCase());
              return (
                <div
                  key={checkKey}
                  data-testid={`check-row-${checkKey}`}
                  className={`p-2.5 rounded-lg border flex items-center justify-between ${
                    passed
                      ? 'bg-emerald-950/20 border-emerald-500/20 text-emerald-300'
                      : 'bg-rose-950/20 border-rose-500/20 text-rose-300'
                  }`}
                >
                  <span className="font-mono text-[11px] truncate">{label}</span>
                  <div className="flex items-center gap-1.5 shrink-0 ml-2">
                    <span
                      data-testid={`check-status-${checkKey}`}
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border uppercase ${
                        passed
                          ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400'
                          : 'bg-rose-500/20 border-rose-500/40 text-rose-400'
                      }`}
                    >
                      {passed ? 'PASSED' : 'FAILED'}
                    </span>
                    {' '}
                    {passed ? (
                      <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" aria-hidden="true" focusable="false" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" aria-hidden="true" focusable="false" />
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Expandable Machine-Readable JSON Verdict */}
        <div className="border border-[#2a2d36] rounded-lg overflow-hidden">
          <button
            onClick={() => setIsJsonOpen(!isJsonOpen)}
            aria-expanded={isJsonOpen}
            aria-controls="verdict-json-viewer"
            className="w-full px-4 py-2.5 bg-slate-900/60 hover:bg-slate-900 flex items-center justify-between text-xs font-mono text-slate-300 transition-colors"
          >
            <div className="flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400 shrink-0" aria-hidden="true" focusable="false" />
              {' '}
              <span>Structured JSON verdict</span>
            </div>
            {isJsonOpen ? (
              <ChevronUp className="w-4 h-4 shrink-0" aria-hidden="true" focusable="false" />
            ) : (
              <ChevronDown className="w-4 h-4 shrink-0" aria-hidden="true" focusable="false" />
            )}
          </button>

          {isJsonOpen && (
            <div id="verdict-json-viewer" className="p-3 bg-slate-950 border-t border-[#2a2d36] relative">
              <button
                onClick={handleCopyJson}
                className="absolute top-4 right-4 p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1 font-mono"
              >
                {copied ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" aria-hidden="true" focusable="false" />
                ) : (
                  <Copy className="w-3.5 h-3.5 shrink-0" aria-hidden="true" focusable="false" />
                )}
                {' '}
                <span>{copied ? 'Copied' : 'Copy JSON'}</span>
              </button>
              <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto p-2 leading-relaxed">
                {JSON.stringify(verdict, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
