import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Activity,
  ArrowUpRight,
  Lock,
  Layers,
  History,
} from 'lucide-react';
import { FirewallVerdict, MockTransaction } from '../types/firewall';

interface OverviewTabProps {
  verdicts: FirewallVerdict[];
  transactions: MockTransaction[];
  balance: number;
  onSelectVerdict: (verdict: FirewallVerdict) => void;
  onNavigateToConsole: () => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  verdicts,
  transactions,
  balance,
  onSelectVerdict,
  onNavigateToConsole,
}) => {
  const total = verdicts.length;
  const approved = verdicts.filter((v) => v.verdict === 'APPROVED').length;
  const blocked = verdicts.filter((v) => v.verdict === 'BLOCKED').length;
  const review = verdicts.filter((v) => v.verdict === 'REVIEW_REQUIRED').length;

  // Threat category breakdown counts
  const threatCounts: Record<string, number> = {};
  for (const v of verdicts) {
    for (const t of v.threat_category) {
      if (t !== 'NONE') {
        threatCounts[t] = (threatCounts[t] || 0) + 1;
      }
    }
  }

  return (
    <div className="space-y-6">
      {/* Top Welcome & System Status Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-gradient-to-r from-[#0f172a] via-[#131e36] to-[#0f172a] border border-cyan-500/20 shadow-lg">
        <div>
          <div className="flex items-center gap-2">
            <span className="inline-block w-2.5 h-2.5 rounded-full bg-cyan-400 motion-safe:animate-pulse"></span>
            <span className="text-xs font-mono font-semibold tracking-wider uppercase text-cyan-300">
              SECURITY OPERATIONS CENTER ACTIVE
            </span>
          </div>
          <h2 className="text-lg sm:text-xl font-bold font-mono text-white mt-1">
            BANKISM Live Telemetry & Threat Surface
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time interceptor metrics for natural-language banking interactions.
          </p>
        </div>

        <button
          onClick={onNavigateToConsole}
          className="self-start sm:self-auto px-4 py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors"
        >
          <span>Launch Analysis Console</span>
          <ArrowUpRight className="w-4 h-4" />
        </button>
      </div>

      {/* Primary KPI Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Analyzed */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono">Total Requests</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-white">{total}</div>
          <div className="text-[11px] text-slate-400 mt-1">Inspected through guardrail pipeline</div>
        </div>

        {/* Approved Requests */}
        <div className="bg-[#0f172a] border border-emerald-500/20 rounded-xl p-4">
          <div className="flex items-center justify-between text-emerald-400 mb-2">
            <span className="text-xs font-mono">Approved</span>
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-emerald-300">{approved}</div>
          <div className="text-[11px] text-slate-400 mt-1">
            {total > 0 ? `${((approved / total) * 100).toFixed(0)}% clearance rate` : 'Awaiting traffic'}
          </div>
        </div>

        {/* Blocked Requests */}
        <div className="bg-[#0f172a] border border-rose-500/20 rounded-xl p-4">
          <div className="flex items-center justify-between text-rose-400 mb-2">
            <span className="text-xs font-mono">Threats Blocked</span>
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-rose-300">{blocked}</div>
          <div className="text-[11px] text-slate-400 mt-1">Injections & overrides halted</div>
        </div>

        {/* Review Required */}
        <div className="bg-[#0f172a] border border-amber-500/20 rounded-xl p-4">
          <div className="flex items-center justify-between text-amber-400 mb-2">
            <span className="text-xs font-mono">Review Required</span>
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-amber-300">{review}</div>
          <div className="text-[11px] text-slate-400 mt-1">Ambiguity or policy boundary</div>
        </div>
      </div>

      {/* Middle Grid: Threat Distribution & Mock Banking Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Distribution Panel */}
        <div className="lg:col-span-2 bg-[#0f172a] border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Observed Threat Distribution
            </h3>
            <span className="text-xs text-slate-400 font-mono">Categorical Heuristics</span>
          </div>

          {Object.keys(threatCounts).length === 0 ? (
            <div className="py-8 text-center text-slate-400 text-xs font-mono">
              No active adversarial attack threats recorded yet. Run test cases in Attack Lab.
            </div>
          ) : (
            <div className="space-y-3">
              {Object.entries(threatCounts).map(([cat, count]) => {
                const percentage = ((count / Math.max(1, blocked + review)) * 100).toFixed(0);
                const formattedCat = cat.replace(/_/g, ' ');
                return (
                  <div key={cat} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="font-mono text-slate-300">{formattedCat}</span>
                      <span className="font-mono text-slate-400">
                        {count} ({percentage}%)
                      </span>
                    </div>
                    <div
                      role="progressbar"
                      aria-valuenow={Number(percentage)}
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-label={`${formattedCat} threat frequency: ${percentage}%`}
                      className="w-full h-2 rounded-full bg-slate-800 overflow-hidden"
                    >
                      <div
                        className="h-full bg-rose-500 rounded-full"
                        style={{ width: `${Math.min(100, Math.max(8, Number(percentage)))}%` }}
                      ></div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Mock Sandbox Status Card */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center gap-2">
                <Lock className="w-4 h-4 text-emerald-400" />
                Sandbox Vault
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                ISOLATED
              </span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 mb-4">
              <div className="text-[11px] text-slate-400 font-mono uppercase">Simulated Checking Balance</div>
              <div className="text-2xl font-bold font-mono text-white mt-1">
                ${balance.toLocaleString('en-US', { minimumFractionDigits: 2 })}
              </div>
              <div className="text-[10px] text-emerald-400 font-mono mt-1">Protected by Server Gate</div>
            </div>

            <div className="text-xs text-slate-400 space-y-1.5 font-mono">
              <div className="flex justify-between">
                <span>Total Executed Tx:</span>
                <span className="text-slate-200">{transactions.length}</span>
              </div>
              <div className="flex justify-between">
                <span>Single Tx Limit:</span>
                <span className="text-slate-200">$1,000.00</span>
              </div>
              <div className="flex justify-between">
                <span>Idempotency Cache:</span>
                <span className="text-emerald-400">ACTIVE</span>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 mt-4 text-[11px] text-slate-400">
            * Pure simulation sandbox. Zero connections to production banking networks or real currency.
          </div>
        </div>
      </div>

      {/* Recent Request Activity Feed */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            Recent Intercepted Activity Log
          </h3>
          <span className="text-xs text-slate-400 font-mono">Showing {Math.min(5, verdicts.length)} items</span>
        </div>

        {verdicts.length === 0 ? (
          <div className="py-6 text-center text-slate-400 text-xs font-mono">
            No firewall requests recorded yet.
          </div>
        ) : (
          <div className="space-y-2.5">
            {verdicts.slice(0, 5).map((v) => (
              <div
                key={v.request_id}
                onClick={() => onSelectVerdict(v)}
                className="p-3 rounded-lg bg-slate-900/70 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-2"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border uppercase ${
                        v.verdict === 'APPROVED'
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                          : v.verdict === 'BLOCKED'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                      }`}
                    >
                      {v.verdict}
                    </span>
                    <span className="text-xs font-mono text-slate-400">{v.request_id}</span>
                    <span className="text-[11px] text-cyan-400 font-mono">[{v.intent}]</span>
                  </div>
                  <p className="text-xs text-slate-300 truncate max-w-xl font-sans">
                    "{v.normalised_request}"
                  </p>
                </div>

                <div className="text-right text-[11px] font-mono text-slate-400 shrink-0">
                  <div>Risk: {v.risk_level}</div>
                  <div className="text-slate-400">{new Date(v.timestamp).toLocaleTimeString()}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
