import { useRef, useState } from 'react';
import { ArrowRight, Check, FlaskConical, Play } from 'lucide-react';
import { SIMULATION_CASES } from '../data/simulationCases';
import type { SimulationCase } from '../data/simulationCases';
import type { FirewallVerdict, AnalyzeRequestPayload } from '../types/firewall';

interface LabTabProps {
  onAnalyze: (payload: AnalyzeRequestPayload) => Promise<{ verdict: FirewallVerdict }>;
  onSelectVerdict: (verdict: FirewallVerdict) => void;
  onNavigateToConsole: (payload: AnalyzeRequestPayload) => void;
}

interface Result {
  verdict?: FirewallVerdict;
  passed: boolean;
}

const filters = [
  { id: 'all', label: 'All cases' },
  { id: 'attack', label: 'Threats' },
  { id: 'benign', label: 'Benign' },
  { id: 'tool', label: 'Tool calls' },
] as const;

export function LabTab({ onAnalyze, onSelectVerdict, onNavigateToConsole }: LabTabProps) {
  const [filter, setFilter] = useState<typeof filters[number]['id']>('all');
  const [results, setResults] = useState<Record<string, Result>>({});
  const [running, setRunning] = useState(false);
  const pending = useRef(false);
  const [progress, setProgress] = useState<{ current: number; total: number }>();

  const cases = SIMULATION_CASES.filter(({ category, payload }) =>
    filter === 'all' ||
    (filter === 'benign' && category === 'BENIGN') ||
    (filter === 'attack' && category !== 'BENIGN') ||
    (filter === 'tool' && payload.tool_call !== undefined)
  );
  const completed = Object.values(results);
  const passed = completed.filter((entry) => entry.passed).length;

  async function run(items: SimulationCase[]) {
    if (pending.current) return;
    pending.current = true;
    setRunning(true);
    if (items.length > 1) setResults({});
    try {
      for (const [index, test] of items.entries()) {
        setProgress({ current: index + 1, total: items.length });
        let result: Result = { passed: false };
        try {
          const { verdict } = await onAnalyze(test.payload);
          const expectedThreat = test.category === 'BENIGN' ? 'NONE' : test.category;
          result = {
            verdict,
            passed: verdict.verdict === test.expectedVerdict &&
              verdict.threat_category.includes(expectedThreat) &&
              !verdict.transaction_executed &&
              verdict.requires_confirmation === (test.expectedVerdict === 'APPROVED' && verdict.intent === 'TRANSFER'),
          };
        } catch {
          // An unavailable analysis API counts as a failed verification.
        }
        setResults((previous) => ({ ...previous, [test.id]: result }));
      }
    } finally {
      pending.current = false;
      setRunning(false);
      setProgress(undefined);
    }
  }

  return (
    <section className="workspace-view lab">
      <div className="workspace-heading dashboard-heading">
        <div>
          <span className="workspace-kicker"><FlaskConical size={15} aria-hidden="true" /> Sandbox verification</span>
          <h1>Prompt lab</h1>
          <p>Run known threat and benign cases against the same policy engine as the console.</p>
        </div>
        <button type="button" className="pill pill-primary" onClick={() => run(SIMULATION_CASES)} disabled={running}>
          <Play size={15} aria-hidden="true" /> {running ? 'Running verification…' : `Run all ${SIMULATION_CASES.length} cases`}
        </button>
      </div>
      <div className="lab-toolbar">
        <div className="lab-filters" aria-label="Filter cases">
          {filters.map(({ id, label }) => <button type="button" key={id} aria-pressed={id === filter} onClick={() => setFilter(id)}>{label}</button>)}
        </div>
        <p role="status">
          {progress ? `Running ${progress.current} of ${progress.total}` : completed.length ? `${passed} of ${completed.length} passed` : 'Ready to run'}
        </p>
      </div>
      <div className="lab-list">
        {cases.map((test) => {
          const result = results[test.id];
          return (
            <article key={test.id} className="lab-case">
              <div className="lab-case-head">
                <span className={`status-label ${test.category === 'BENIGN' ? 'approved' : 'neutral'}`}>
                  {test.category.toLowerCase().replaceAll('_', ' ')}
                </span>
                {result && <span className={`status-label ${result.passed ? 'approved' : 'blocked'}`}>
                  {result.passed ? <><Check size={13} /> Passed</> : 'Failed'}
                </span>}
              </div>
              <h2>{test.title}</h2>
              <p>{test.description}</p>
              <details>
                <summary>Request payload</summary>
                <pre>{JSON.stringify(test.payload, null, 2)}</pre>
              </details>
              <dl className="lab-signals">
                <div><dt>Expected</dt><dd>{test.expectedVerdict.replaceAll('_', ' ')} · {test.category === 'BENIGN' ? 'NONE' : test.category.replaceAll('_', ' ')}</dd></div>
                {result && <div><dt>Observed</dt><dd>{result.verdict ? `${result.verdict.verdict.replaceAll('_', ' ')} · ${result.verdict.threat_category.join(', ').replaceAll('_', ' ')}` : 'API error'}</dd></div>}
              </dl>
              <div className="lab-case-actions">
                <button type="button" className="text-button" onClick={() => onNavigateToConsole(test.payload)}>Load in console <ArrowRight size={14} /></button>
                {result?.verdict && <button type="button" className="text-button" onClick={() => onSelectVerdict(result.verdict!)}>Inspect verdict</button>}
                <button type="button" className="small-button" onClick={() => run([test])} disabled={running}>Test case</button>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
