import React from 'react';
import { Shield, Cpu, Activity, Lock } from 'lucide-react';
import { EngineMode } from '../types/firewall';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  engineMode: EngineMode;
  totalRequests: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  engineMode,
  totalRequests,
}) => {
  const tabs = [
    { id: 'overview', label: 'SOC Overview' },
    { id: 'console', label: 'Analysis Console' },
    { id: 'lab', label: 'Attack Simulation Lab' },
    { id: 'sandbox', label: 'Mock Banking Sandbox' },
    { id: 'architecture', label: 'Security Architecture' },
    { id: 'docs', label: 'Docs & API' },
  ];

  return (
    <header className="border-b border-slate-800 bg-[#0a1124]/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & System Brand */}
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
              <Shield className="w-6 h-6" />
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="motion-safe:animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-bold tracking-wider text-white font-mono">BANKISM</span>
                <span className="text-[10px] font-semibold tracking-wider uppercase px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  AI FIREWALL v1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Blue-Team LLM Guardrails &amp; Deterministic Authorization Gate
              </p>
            </div>
          </div>

          {/* Engine Status & Badges */}
          <div className="hidden md:flex items-center gap-3 text-xs">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-300">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>Engine:</span>
              <span className="font-mono text-cyan-400 font-medium">
                {engineMode === 'DETERMINISTIC_RULES' ? 'Deterministic Rules' : 'Hybrid Advisory LLM'}
              </span>
            </div>

            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-300">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>Policy:</span>
              <span className="font-mono text-emerald-400 font-medium">Fail-Closed</span>
            </div>

            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-300">
              <Activity className="w-3.5 h-3.5 text-indigo-400" />
              <span>Requests:</span>
              <span className="font-mono text-indigo-300 font-semibold">{totalRequests}</span>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav role="tablist" aria-label="Security Operations Navigation" className="flex space-x-1 sm:space-x-2 border-t border-slate-800/60 overflow-x-auto py-2">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                id={`tab-${tab.id}`}
                role="tab"
                aria-selected={isActive}
                aria-controls={`tabpanel-${tab.id}`}
                tabIndex={isActive ? 0 : -1}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 text-xs sm:text-sm font-medium rounded-md whitespace-nowrap transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-[0_0_10px_rgba(6,182,212,0.15)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
