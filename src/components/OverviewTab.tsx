import { useState } from 'react';
import { Activity, ArrowRight, ArrowUpRight, Check, Clock3, LockKeyhole, ShieldAlert } from 'lucide-react';
import type { EngineMode, FirewallVerdict, MockTransaction, Verdict } from '../types/firewall';

const DECISIONS = [
  { id: 'APPROVED', label: 'Approved', short: 'Approved', icon: Check, tone: 'approved' },
  { id: 'BLOCKED', label: 'Blocked', short: 'Blocked', icon: ShieldAlert, tone: 'blocked' },
  { id: 'REVIEW_REQUIRED', label: 'Needs review', short: 'Review', icon: Clock3, tone: 'review' },
] as const;

const ENGINE_LABELS: Record<EngineMode, string> = {
  DETERMINISTIC_RULES: 'Deterministic rules',
  HYBRID_LLM_ADVISORY: 'Hybrid advisory',
  FAIL_CLOSED: 'Fail-closed',
};

const currency = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' });

interface OverviewTabProps {
  verdicts: FirewallVerdict[];
  transactions: MockTransaction[];
  balance: number;
  engineMode: EngineMode;
  showingSamples: boolean;
  onSelectVerdict: (verdict: FirewallVerdict) => void;
}

export function OverviewTab({ verdicts, transactions, balance, engineMode, showingSamples, onSelectVerdict }: OverviewTabProps) {
  const [decision, setDecision] = useState<Verdict | 'all'>('all');
  const [source, setSource] = useState('all');
  const counts = DECISIONS.map(({ id }) => verdicts.filter((entry) => entry.verdict === id).length);
  const toolCount = verdicts.filter((entry) => entry.request_source === 'TOOL_CALL').length;
  const proposalCount = verdicts.filter((entry) => entry.requires_confirmation && !entry.simulation).length;
  const threats = new Map<string, number>();
  for (const entry of verdicts) {
    for (const category of new Set(entry.threat_category)) {
      if (category !== 'NONE') threats.set(category, (threats.get(category) ?? 0) + 1);
    }
  }
  const threatRows = [...threats].sort((left, right) => right[1] - left[1]);
  const results = verdicts.filter((entry) =>
    (decision === 'all' || decision === entry.verdict) &&
    (source === 'all' || source === (entry.request_source ?? 'PROMPT'))
  );

  return (
    <section className="workspace-view dashboard" aria-labelledby="dashboard-heading">
      <div className="workspace-heading dashboard-heading">
        <div>
          <span className="workspace-kicker"><span /> {showingSamples ? 'Sample activity' : 'Session activity'}</span>
          <h1 id="dashboard-heading">Security dashboard</h1>
          <p>Review policy decisions, flagged threats, and mock transfers.</p>
        </div>
        <a className="pill pill-primary" href="#console">Analyze a request <ArrowRight size={16} aria-hidden="true" /></a>
      </div>
      <div className="dashboard-meta">
        <span><Activity size={15} aria-hidden="true" /> {ENGINE_LABELS[engineMode]}</span>
        <span>{toolCount} tool {toolCount === 1 ? 'call' : 'calls'}</span>
        <span>{proposalCount} transfer {proposalCount === 1 ? 'proposal' : 'proposals'}</span>
      </div>
      <div className="dashboard-layout">
        <section className="dashboard-panel decision-panel" aria-labelledby="decisions-heading">
          <header><h2 id="decisions-heading">Policy decisions</h2><span>{verdicts.length} total</span></header>
          <div className="decision-stats">
            {DECISIONS.map(({ id, label, tone, icon: Icon }, index) => (
              <div key={id} className={`decision-count ${tone}`}>
                <span><Icon size={14} aria-hidden="true" /> {label}</span>
                <strong>{counts[index]}</strong>
              </div>
            ))}
          </div>
          <div className="decision-bar" aria-hidden="true">
            {DECISIONS.map(({ id, tone }, index) =>
              counts[index] > 0 && <span key={id} className={tone} style={{ flex: counts[index] }} />
            )}
          </div>
        </section>
        <section className="dashboard-panel ledger-panel" aria-labelledby="ledger-heading">
          <header><h2 id="ledger-heading"><LockKeyhole size={15} aria-hidden="true" /> Mock ledger</h2><a href="#sandbox" aria-label="Open mock ledger"><ArrowUpRight size={18} aria-hidden="true" /></a></header>
          <strong>{currency.format(balance)}</strong>
          <p>{transactions.filter(({ type, status }) => type === 'TRANSFER' && status === 'COMPLETED').length} completed transfers</p>
        </section>
        <section className="dashboard-panel activity-panel" aria-labelledby="activity-heading">
          <header><h2 id="activity-heading">Request activity</h2><span>{Math.min(results.length, 8)} of {results.length} shown</span></header>
          <div className="activity-filters">
            <label><span className="sr-only">Filter by verdict</span>
              <select value={decision} onChange={(event) => setDecision(event.target.value as typeof decision)}>
                <option value="all">All decisions</option>
                {DECISIONS.map(({ id, label }) => <option key={id} value={id}>{label}</option>)}
              </select>
            </label>
            <label><span className="sr-only">Filter by source</span>
              <select value={source} onChange={(event) => setSource(event.target.value)}>
                <option value="all">All sources</option>
                <option value="TOOL_CALL">Agent tool calls</option>
                <option value="PROMPT">Banking prompts</option>
              </select>
            </label>
          </div>
          {results.length ? <ul className="activity-list">
            {results.slice(0, 8).map((entry) => {
              const status = DECISIONS.find(({ id }) => id === entry.verdict)!;
              return (
                <li key={entry.request_id}>
                  <button className="activity-row" onClick={() => onSelectVerdict(entry)}>
                    <span className={`status-label ${status.tone}`}>{status.short}</span>
                    <span className="activity-description">
                      <strong>{entry.normalised_request || entry.tool_name || 'Request failed validation'}</strong>
                      <span>{entry.request_source === 'TOOL_CALL' ? entry.tool_name || 'Agent tool call' : 'Banking prompt'}
                        {entry.simulation && ' · Lab case'}{entry.transaction_executed && ' · Transfer recorded'}</span>
                    </span>
                    <time dateTime={entry.timestamp}>{new Date(entry.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}</time>
                    <ArrowUpRight size={15} aria-hidden="true" />
                  </button>
                </li>
              );
            })}
          </ul> : <p className="empty-state">No decisions match these filters.</p>}
        </section>
        <section className="dashboard-panel threat-panel" aria-labelledby="threat-heading">
          <header><h2 id="threat-heading">Flagged threats</h2></header>
          {threatRows.length ? <ul>
            {threatRows.map(([category, count]) => (
              <li key={category}>
                <div><span>{category.toLowerCase().replaceAll('_', ' ')}</span><strong>{count}</strong></div>
                <span className="threat-bar" aria-hidden="true"><span style={{ width: `${count / verdicts.length * 100}%` }} /></span>
              </li>
            ))}
          </ul> : <p className="empty-state">No threats flagged in this session.</p>}
          <a className="text-link" href="#lab">Open prompt lab <ArrowRight size={15} aria-hidden="true" /></a>
        </section>
      </div>
    </section>
  );
}
