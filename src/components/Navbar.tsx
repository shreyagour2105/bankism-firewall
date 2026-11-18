import { ArrowRight, Github, Shield } from 'lucide-react';

export const REPOSITORY_URL = 'https://github.com/shreyagour2105/bankism-firewall';

const workspacePages = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'console', label: 'Console' },
  { id: 'lab', label: 'Prompt lab' },
  { id: 'sandbox', label: 'Mock ledger' },
  { id: 'architecture', label: 'Architecture' },
  { id: 'docs', label: 'Documentation' },
] as const;

type Page = 'home' | typeof workspacePages[number]['id'];

export function getPage(): Page {
  const hash = window.location.hash.slice(1);
  return workspacePages.find(({ id }) => id === hash)?.id ?? 'home';
}

export function Navbar({ page }: { page: Page }) {
  return (
    <header className={page === 'home' ? 'site-header is-home' : 'site-header'}>
      <div className="wrap nav-row">
        <a className="wordmark" href="#home" aria-label="Bankism Firewall home">
          <span className="brand-icon"><Shield size={21} strokeWidth={1.75} aria-hidden="true" /></span>
          <span>Bankism <span>Firewall</span></span>
        </a>
        <nav aria-label="Site navigation" className="site-nav">
          <a href="#controls">Controls</a>
          {page === 'home' && <a href="#dashboard">Dashboard</a>}
          <a href="#architecture" aria-current={page === 'architecture' ? 'page' : undefined}>Architecture</a>
          <a href="#docs" aria-current={page === 'docs' ? 'page' : undefined}>Docs</a>
        </nav>
        <div className="nav-actions">
          <a className="github-link" href={REPOSITORY_URL} aria-label="Bankism Firewall on GitHub"><Github size={17} aria-hidden="true" /><span>GitHub</span></a>
          <a className="pill pill-outline" href="#console">Open console <ArrowRight size={15} aria-hidden="true" /></a>
        </div>
      </div>
      {page !== 'home' && (
        <nav className="workspace-nav" aria-label="Demo workspace">
          <div className="wrap">
            {workspacePages.map(({ id, label }) => (
              <a key={id} href={`#${id}`} aria-current={page === id ? 'page' : undefined}>{label}</a>
            ))}
          </div>
        </nav>
      )}
    </header>
  );
}
