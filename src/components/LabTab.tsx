import React, { useState } from 'react';
import {
  Play,
  CheckCircle,
  XCircle,
  Terminal,
  Filter,
  Check,
} from 'lucide-react';
import { SIMULATION_CASES, SimulationCase } from '../data/simulationCases';
import { FirewallVerdict, AnalyzeRequestPayload } from '../types/firewall';

interface LabTabProps {
  onAnalyze: (payload: AnalyzeRequestPayload) => Promise<{ verdict: FirewallVerdict; verdictToken?: string }>;
  onSelectVerdict: (verdict: FirewallVerdict) => void;
  onNavigateToConsole: (payload: AnalyzeRequestPayload) => void;
}

interface TestRunResult {
  caseId: string;
  expected: string;
  actual: string;
  passed: boolean;
  verdict: FirewallVerdict;
}

export const LabTab: React.FC<LabTabProps> = ({
  onAnalyze,
  onSelectVerdict,
  onNavigateToConsole,
}) => {
  const [selectedFilter, setSelectedFilter] = useState<'ALL' | 'ATTACK' | 'BENIGN'>('ALL');
  const [runningSuite, setRunningSuite] = useState(false);
  const [testResults, setTestResults] = useState<Record<string, TestRunResult>>({});
  const [suiteProgress, setSuiteProgress] = useState<{ current: number; total: number } | null>(null);

  const filteredCases = SIMULATION_CASES.filter((c) => {
    if (selectedFilter === 'ALL') return true;
    if (selectedFilter === 'BENIGN') return c.category === 'BENIGN';
    if (selectedFilter === 'ATTACK') return c.category !== 'BENIGN';
    return true;
  });

  // Run full automated simulation suite live
  const handleRunAllTests = async () => {
    setRunningSuite(true);
    const results: Record<string, TestRunResult> = {};

    for (let i = 0; i < SIMULATION_CASES.length; i++) {
      const tc = SIMULATION_CASES[i];
      setSuiteProgress({ current: i + 1, total: SIMULATION_CASES.length });

      try {
        const { verdict } = await onAnalyze(tc.payload);
        const passed = verdict.verdict === tc.expectedVerdict;
        results[tc.id] = {
          caseId: tc.id,
          expected: tc.expectedVerdict,
          actual: verdict.verdict,
          passed,
          verdict,
        };
      } catch {
        // If error, mark failed
        results[tc.id] = {
          caseId: tc.id,
          expected: tc.expectedVerdict,
          actual: 'ERROR',
          passed: false,
          verdict: null as any,
        };
      }
    }

    setTestResults(results);
    setRunningSuite(false);
    setSuiteProgress(null);
  };

  // Run single test
  const handleRunSingle = async (tc: SimulationCase) => {
    try {
      const { verdict } = await onAnalyze(tc.payload);
      const passed = verdict.verdict === tc.expectedVerdict;
      setTestResults((prev) => ({
        ...prev,
        [tc.id]: {
          caseId: tc.id,
          expected: tc.expectedVerdict,
          actual: verdict.verdict,
          passed,
          verdict,
        },
      }));
      onSelectVerdict(verdict);
    } catch (e) {
      console.error(e);
    }
  };

  const completedCount = Object.keys(testResults).length;
  const passedCount = Object.values(testResults).filter((r) => r.passed).length;

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-[#0f172a] border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <h2 className="text-xl font-bold font-mono text-white">Attack Simulation & Verification Lab</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Execute real-world prompt injection, jailbreaks, malicious memos, obfuscations, and boundary cases against the firewall.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRunAllTests}
            disabled={runningSuite}
            className="px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono flex items-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all disabled:opacity-50"
          >
            {runningSuite ? (
              <>
                <span className="animate-spin">⚙</span>
                <span>Testing ({suiteProgress?.current}/{suiteProgress?.total})...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Run Full Security Suite (12 Cases)</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Filter and Scoreboard */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-[#0f172a] border border-slate-800 rounded-xl p-4">
        {/* Filter Pills */}
        <div className="flex items-center gap-2 text-xs">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-400 font-mono">Filter:</span>
          {(['ALL', 'ATTACK', 'BENIGN'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setSelectedFilter(mode)}
              className={`px-3 py-1 rounded-md text-xs font-mono font-medium transition-colors ${
                selectedFilter === mode
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {mode}
            </button>
          ))}
        </div>

        {/* Live Scoreboard */}
        {completedCount > 0 && (
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="text-slate-400">Suite Results:</span>
            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold">
              {passedCount} / {completedCount} Passed
            </span>
            {passedCount === completedCount && (
              <span className="text-emerald-400 flex items-center gap-1">
                <Check className="w-3.5 h-3.5" aria-hidden="true" focusable="false" />{' '}<span>100% Guardrail Integrity</span>
              </span>
            )}
          </div>
        )}
      </div>

      {/* Simulation Cases Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredCases.map((tc) => {
          const runResult = testResults[tc.id];
          const isAttack = tc.category !== 'BENIGN';

          return (
            <div
              key={tc.id}
              className={`p-5 rounded-xl border transition-all flex flex-col justify-between ${
                runResult
                  ? runResult.passed
                    ? 'bg-[#0e1b2e] border-emerald-500/30'
                    : 'bg-[#1e1018] border-rose-500/40'
                  : 'bg-[#0f172a] border-slate-800 hover:border-slate-700'
              }`}
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="space-y-1">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-bold border ${
                        isAttack
                          ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                          : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                      }`}
                    >
                      {tc.category}
                    </span>
                    <h3 className="text-sm font-bold font-mono text-white">{tc.title}</h3>
                  </div>

                  {/* Pass/Fail Status if tested */}
                  {runResult && (
                    <div className="shrink-0">
                      {runResult.passed ? (
                        <span className="flex items-center gap-1 text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-500/40 px-2 py-1 rounded">
                          <CheckCircle className="w-3.5 h-3.5" aria-hidden="true" focusable="false" />{' '}<span>PASS</span>
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-xs font-mono text-rose-400 bg-rose-950/60 border border-rose-500/40 px-2 py-1 rounded">
                          <XCircle className="w-3.5 h-3.5" aria-hidden="true" focusable="false" />{' '}<span>FAIL</span>
                        </span>
                      )}
                    </div>
                  )}
                </div>

                <p className="text-xs text-slate-400 mb-3">{tc.description}</p>

                {/* Input Payload Preview */}
                <div className="p-2.5 rounded bg-[#080d1a] border border-slate-800 font-mono text-[11px] text-slate-300 break-all mb-3">
                  <span className="text-slate-500">Payload: </span>
                  "{tc.payload.raw_input}"
                  {tc.payload.memo && (
                    <div className="text-rose-400 mt-1">
                      <span className="text-slate-500">Memo: </span>"{tc.payload.memo}"
                    </div>
                  )}
                </div>
              </div>

              {/* Footer Actions & Verdict Comparison */}
              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <div className="font-mono text-[11px] text-slate-400">
                  Expected: <strong className="text-white">{tc.expectedVerdict}</strong>
                  {runResult && (
                    <>
                      {' '}
                      • Actual: <strong className="text-cyan-400">{runResult.actual}</strong>
                    </>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => onNavigateToConsole(tc.payload)}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-[11px] transition-colors"
                  >
                    Load in Console
                  </button>

                  <button
                    onClick={() => handleRunSingle(tc)}
                    className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-mono text-[11px] flex items-center gap-1 transition-colors"
                  >
                    <span>Test Now</span>
                    <Play className="w-3 h-3" />
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
