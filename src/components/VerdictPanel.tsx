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
  Zap,
} from 'lucide-react';
import { FirewallVerdict } from '../types/firewall';

interface VerdictPanelProps {
  verdict: FirewallVerdict | null;
  verdictToken?: string;
  onExecuteTransfer?: (verdict: FirewallVerdict, token: string) => void;
  isExecuting?: boolean;
  executionResult?: { success: boolean; message: string; txId?: string } | null;
}

export const VerdictPanel: React.FC<VerdictPanelProps> = ({
  verdict,
  verdictToken,
  onExecuteTransfer,
  isExecuting = false,
  executionResult = null,
}) => {
  const [copied, setCopied] = useState(false);
  const [isJsonOpen, setIsJsonOpen] = useState(false);

  if (!verdict) {
    return (
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-8 text-center text-slate-500">
        <ShieldCheck className="w-12 h-12 mx-auto mb-3 opacity-30 text-cyan-400" />
        <h4 className="text-sm font-semibold text-slate-400 mb-1">Awaiting Security Evaluation</h4>
        <p className="text-xs max-w-sm mx-auto text-slate-500">
          Submit a natural language banking request or select an attack simulation test case above to trigger the firewall pipeline.
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
      icon: <CheckCircle className="w-6 h-6 text-emerald-400" />,
      title: 'APPROVED — REQUEST CLEARED',
    },
    BLOCKED: {
      bg: 'bg-rose-950/40 border-rose-500/40 text-rose-400',
      badge: 'bg-rose-500/20 text-rose-300 border-rose-500/50',
      icon: <XCircle className="w-6 h-6 text-rose-400" />,
      title: 'BLOCKED — THREAT NEUTRALIZED',
    },
    REVIEW_REQUIRED: {
      bg: 'bg-amber-950/40 border-amber-500/40 text-amber-400',
      badge: 'bg-amber-500/20 text-amber-300 border-amber-500/50',
      icon: <AlertTriangle className="w-6 h-6 text-amber-400" />,
      title: 'REVIEW REQUIRED — POLICY BOUNDARY',
    },
  }[verdict.verdict];

  // Risk Level visual styles
  const riskBadgeStyles = {
    LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    CRITICAL: 'bg-rose-500/20 text-rose-400 border-rose-500/50 animate-pulse',
  }[verdict.risk_level];

  return (
    <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      {/* Top Banner Verdict Header */}
      <div className={`p-4 sm:p-5 border-b ${verdictStyles.bg} flex flex-wrap items-center justify-between gap-3`}>
        <div className="flex items-center gap-3">
          {verdictStyles.icon}
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-base sm:text-lg tracking-wide">
                {verdictStyles.title}
              </span>
              <span className={`text-[11px] font-mono px-2 py-0.5 rounded border uppercase font-semibold ${riskBadgeStyles}`}>
                RISK: {verdict.risk_level}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Request ID: <span className="font-mono text-slate-300">{verdict.request_id}</span> • Latency:{' '}
              <span className="font-mono text-cyan-400">{verdict.latency_ms}ms</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs px-2.5 py-1 rounded bg-slate-900/80 border border-slate-700/60 font-mono text-slate-300">
            Intent: <strong className="text-white">{verdict.intent}</strong>
          </span>
        </div>
      </div>

      <div className="p-4 sm:p-6 space-y-6">
        {/* Rationale Section */}
        <div>
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
            Decision Rationale
          </h4>
          <div className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 text-sm text-slate-200 leading-relaxed font-sans">
            {verdict.rationale}
          </div>
        </div>

        {/* Threat Categories Detected */}
        <div>
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
            Threat Categories Flagged
          </h4>
          <div className="flex flex-wrap gap-2">
            {verdict.threat_category.map((cat, idx) => (
              <span
                key={idx}
                className={`text-xs px-2.5 py-1 rounded-md font-mono border ${
                  cat === 'NONE'
                    ? 'bg-slate-800/60 text-slate-400 border-slate-700'
                    : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                }`}
              >
                {cat}
              </span>
            ))}
          </div>
        </div>

        {/* Individual Policy Checks Grid */}
        <div>
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Deterministic Security Checks
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
            {Object.entries(verdict.checks).map(([checkKey, passed]) => {
              const label = checkKey
                .replace(/_/g, ' ')
                .replace(/\b\w/g, (c) => c.toUpperCase());
              return (
                <div
                  key={checkKey}
                  className={`p-2.5 rounded-lg border flex items-center justify-between ${
                    passed
                      ? 'bg-emerald-950/20 border-emerald-500/20 text-emerald-300'
                      : 'bg-rose-950/20 border-rose-500/20 text-rose-300'
                  }`}
                >
                  <span className="font-mono text-[11px] truncate">{label}</span>
                  {passed ? (
                    <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 ml-1" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-400 shrink-0 ml-1" />
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Separation of Analysis vs Execution Notice */}
        <div className="p-3 rounded-lg bg-cyan-950/20 border border-cyan-500/20 text-xs text-cyan-200/90 flex items-start gap-2.5">
          <Zap className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <strong>Defense Architecture Notice:</strong> Analysis approval verifies policy clearance only.
            Privileged banking actions can NEVER execute client-side and require passing the second server-side authorization gate.
          </div>
        </div>

        {/* Action Gate: Execute Mock Transfer if Approved */}
        {verdict.verdict === 'APPROVED' && verdict.intent === 'TRANSFER' && (
          <div className="p-4 rounded-xl bg-slate-900 border border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.08)]">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h5 className="text-sm font-semibold text-emerald-400 flex items-center gap-1.5">
                  <UserCheck className="w-4 h-4" />
                  Eligible for Mock Transfer Execution
                </h5>
                <p className="text-xs text-slate-400 mt-0.5">
                  Amount: <span className="font-mono text-white font-semibold">${verdict.extracted_parameters?.amount}</span> • Recipient:{' '}
                  <span className="font-mono text-cyan-400 font-semibold">{verdict.extracted_parameters?.recipient}</span>
                </p>
              </div>

              {verdictToken && onExecuteTransfer && (
                <button
                  onClick={() => onExecuteTransfer(verdict, verdictToken)}
                  disabled={isExecuting || executionResult?.success}
                  className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
                    executionResult?.success
                      ? 'bg-slate-800 text-slate-400 cursor-default'
                      : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold shadow-[0_0_15px_rgba(16,185,129,0.3)]'
                  }`}
                >
                  {isExecuting ? (
                    'Executing via Gate...'
                  ) : executionResult?.success ? (
                    'Transfer Executed ✓'
                  ) : (
                    <>
                      <span>Submit to Transaction Gate</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              )}
            </div>

            {/* Execution Result Banner */}
            {executionResult && (
              <div
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

        {/* Expandable Machine-Readable JSON Verdict */}
        <div className="border border-slate-800 rounded-lg overflow-hidden">
          <button
            onClick={() => setIsJsonOpen(!isJsonOpen)}
            className="w-full px-4 py-2.5 bg-slate-900/60 hover:bg-slate-900 flex items-center justify-between text-xs font-mono text-slate-300 transition-colors"
          >
            <div className="flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" />
              <span>Structured JSON Verdict (Schema v1.0)</span>
            </div>
            {isJsonOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {isJsonOpen && (
            <div className="p-3 bg-slate-950 border-t border-slate-800 relative">
              <button
                onClick={handleCopyJson}
                className="absolute top-4 right-4 p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1 font-mono"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
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
