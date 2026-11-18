import {
  ArrowRight, ArrowUpRight, Braces, Check, FileCode2, Github, Layers3,
  ListChecks, ScanLine, ShieldCheck, Workflow,
} from 'lucide-react';
import { REPOSITORY_URL } from './Navbar';

const controls = [
  {
    title: 'Validate tool calls',
    description: 'Allowlisted tools, strict JSON arguments, and deterministic transaction limits.',
    icon: Braces,
    detail: <pre className="tool-example"><span>POST</span> /api/analyze{'\n\n'}{'{ "tool_call": {'}{'\n'}{'  "name": '}<em>"get_balance"</em>,{'\n'}{'  "arguments": {}'}{'\n'}{'}}'}</pre>,
  },
  {
    title: 'Require explicit consent',
    description: 'Show the exact amount, recipient, and memo before the mock ledger can be debited.',
    icon: ListChecks,
    detail: <div className="consent-steps"><span><Check size={15} /> Policy approved</span><div /><span><Check size={15} /> Consent recorded</span><div /><span><Check size={15} /> Transfer logged</span></div>,
  },
  {
    title: 'Test prompt defenses',
    description: 'Compare expected verdicts and threat categories with the firewall’s actual output.',
    icon: ScanLine,
    detail: <div className="scan-example"><span className="status-label blocked">Blocked</span><code>Prompt injection</code><span className="status-label approved">Approved</span><code>Benign balance inquiry</code></div>,
  },
];

export function LandingPage() {
  return (
    <main id="home-main" tabIndex={-1} className="landing">
      <section id="home" className="hero">
        <div className="hero-beam" aria-hidden="true" />
        <div className="wrap hero-inner">
          <div className="hero-copy">
            <p className="eyebrow"><span /> AI security prototype</p>
            <h1>A firewall for<br /><span>AI banking.</span></h1>
            <p className="hero-description">Inspect what an agent wants to do, enforce banking policy, and require explicit approval before a transfer reaches the mock ledger.</p>
            <div className="hero-actions">
              <a className="pill pill-primary" href="#console">See it in action <ArrowRight size={17} aria-hidden="true" /></a>
              <a className="text-link" href="#architecture">Explore the architecture <ArrowUpRight size={15} aria-hidden="true" /></a>
            </div>
          </div>
          <figure className="hero-figure">
            <a className="product-frame" href="#dashboard" aria-label="Open the interactive security dashboard">
              <div className="product-titlebar"><span className="window-dots" aria-hidden="true"><i /><i /><i /></span><span>Bankism Firewall / Dashboard</span><ArrowUpRight size={15} aria-hidden="true" /></div>
              <img src="/screenshots/dashboard.webp" width="1440" height="685" fetchPriority="high"
                alt="Bankism security dashboard with approved, blocked, and review verdicts, recent activity, and the mock ledger balance." />
            </a>
            <figcaption><span><i /> Security dashboard</span><span>Sample activity from the interactive demo</span></figcaption>
          </figure>
          <nav className="capability-strip" aria-label="Explore the demo">
            <a href="#console"><Braces size={16} /> Request analysis</a>
            <a href="#lab"><ScanLine size={16} /> Prompt lab</a>
            <a href="#dashboard"><Layers3 size={16} /> Policy telemetry</a>
            <a href="#sandbox"><ShieldCheck size={16} /> Mock ledger</a>
          </nav>
        </div>
      </section>

      <section className="landing-section light-section" id="controls">
        <div className="wrap">
          <div className="section-heading">
            <div><p className="section-label"><Workflow size={16} /> Policy controls</p><h2>From agent intent<br />to a policy decision.</h2></div>
            <p>Bankism checks natural-language requests and structured tool calls against the same rules. An optional AI analysis can flag risks. The policy engine owns the verdict.</p>
          </div>
          <div className="controls-grid">
            {controls.map(({ title, description, icon: Icon, detail }) => (
              <article key={title} className="control-card">
                <div className="control-detail">{detail}</div>
                <div className="control-caption"><Icon size={19} aria-hidden="true" /><p><strong>{title}.</strong> {description}</p></div>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="landing-section dark-section">
        <div className="wrap showcase-grid">
          <div className="showcase-copy">
            <p className="section-label"><ShieldCheck size={16} /> Transaction consent</p>
            <h2>Policy approval.<br />Then consent.</h2>
            <p>Review the payment in the console. After you confirm, the server issues a short-lived grant tied to the reviewed details and the request’s idempotency key.</p>
            <a className="text-link" href="#console">Open the analysis console <ArrowRight size={17} aria-hidden="true" /></a>
          </div>
          <figure className="showcase-figure">
            <img src="/screenshots/consent.webp" width="950" height="634" loading="lazy"
              alt="Bankism console showing a policy-cleared transfer with amount, recipient, memo, and the required consent checkbox." />
          </figure>
        </div>
      </section>

      <section className="landing-section light-section">
        <div className="wrap lab-showcase">
          <div className="section-heading">
            <div><p className="section-label"><ScanLine size={16} /> Prompt lab</p><h2>See what gets<br />through.</h2></div>
            <div><p>Run the built-in regression suite or inspect a case individually. Each case checks the verdict and the expected threat signal against the sandbox API.</p>
              <a className="text-link" href="#lab">Run the prompt lab <ArrowRight size={17} aria-hidden="true" /></a></div>
          </div>
          <figure className="lab-preview"><img src="/screenshots/lab.webp" width="1440" height="475" loading="lazy"
            alt="Bankism prompt lab showing the verification suite results and expected and observed signals for sample cases." /></figure>
        </div>
      </section>

      <section className="landing-section final-section">
        <div className="wrap final-section-inner">
          <div>
            <p className="section-label"><FileCode2 size={16} /> Developer resources</p>
            <h2>Inspect the firewall.</h2>
            <p>Trace a policy decision in the demo or read the API reference and source.</p>
          </div>
          <div className="hero-actions">
            <a className="pill pill-primary" href="#docs">Read the API docs <ArrowRight size={17} aria-hidden="true" /></a>
            <a className="pill pill-outline" href={REPOSITORY_URL}><Github size={17} aria-hidden="true" /> View source <ArrowUpRight size={15} aria-hidden="true" /></a>
          </div>
        </div>
      </section>
    </main>
  );
}
