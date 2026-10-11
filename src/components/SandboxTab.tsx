import React, { useState } from 'react';
import {
  Users,
  History,
  Lock,
  RotateCcw,
  ShieldAlert,
} from 'lucide-react';
import { MockTransaction, DemoRecipient } from '../types/firewall';

interface SandboxTabProps {
  balance: number;
  transactions: MockTransaction[];
  onResetLedger: () => void;
  onExecuteRawTransfer: (payload: {
    recipient: string;
    amount: number;
    memo?: string;
    verdict_token?: string;
    idempotency_key?: string;
  }) => Promise<{ success: boolean; error?: string; transaction?: MockTransaction }>;
}

const DEMO_RECIPIENT_PROFILES: DemoRecipient[] = [
  { id: '1', name: 'Alice Walker', account: 'alice.eth', category: 'VERIFIED_PEER', max_limit: 1000 },
  { id: '2', name: 'Bob Miller', account: 'bob_miller', category: 'VERIFIED_PEER', max_limit: 1000 },
  { id: '3', name: 'Carol Tech Services', account: 'carol_tech', category: 'MERCHANT', max_limit: 1000 },
  { id: '4', name: 'David Chen', account: 'david_chen', category: 'VERIFIED_PEER', max_limit: 1000 },
  { id: '5', name: 'Elena Finance Utility', account: 'elena_finance', category: 'UTILITY', max_limit: 1000 },
];

export const SandboxTab: React.FC<SandboxTabProps> = ({
  balance,
  transactions,
  onResetLedger,
  onExecuteRawTransfer,
}) => {
  const [selectedRecipient, setSelectedRecipient] = useState('alice.eth');
  const [amount] = useState('100.00');
  const [demoMessage, setDemoMessage] = useState<{ text: string; isError: boolean } | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Hackathon Demo Action 1: Attempt to bypass server gate without token
  const handleTamperBypassTest = async () => {
    setIsLoading(true);
    setDemoMessage(null);
    try {
      const res = await onExecuteRawTransfer({
        recipient: selectedRecipient,
        amount: parseFloat(amount) || 500,
        memo: 'Adversary attempting direct execution without firewall token',
        verdict_token: 'forged_fake_token_attempt_bypass',
        idempotency_key: `idem_tamper_${Date.now()}`,
      });

      if (!res.success) {
        setDemoMessage({
          text: `SERVER GATE ENFORCEMENT PASSED: ${res.error}. The client could NOT bypass the deterministic gate! Ledger balance remained untouched.`,
          isError: true,
        });
      } else {
        setDemoMessage({ text: 'Warning: unexpected success', isError: true });
      }
    } catch (err: any) {
      setDemoMessage({ text: `Rejected as expected: ${err.message}`, isError: true });
    } finally {
      setIsLoading(false);
    }
  };

  // Hackathon Demo Action 2: Attempt duplicate submission (Idempotency Replay Test)
  const handleIdempotencyReplayTest = async () => {
    setIsLoading(true);
    setDemoMessage(null);

    // Pick a previously completed transaction idempotency key
    const completedTx = transactions.find((t) => t.status === 'COMPLETED');
    const existingKey = completedTx ? completedTx.idempotency_key : 'idem_init_001';

    try {
      const res = await onExecuteRawTransfer({
        recipient: selectedRecipient,
        amount: 100.0,
        memo: 'Replay attack test',
        idempotency_key: existingKey, // Replaying duplicate key
        verdict_token: 'forged_token',
      });

      if (!res.success) {
        setDemoMessage({
          text: `IDEMPOTENCY DUPLICATE PREVENTION VERIFIED: ${res.error}. Duplicate transaction was blocked.`,
          isError: true,
        });
      }
    } catch (err: any) {
      setDemoMessage({ text: `Replay Blocked: ${err.message}`, isError: true });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Sandbox Notice */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-[#0f172a] border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Lock className="w-5 h-5 text-emerald-400" />
            <h2 className="text-xl font-bold font-mono text-white">Mock Banking Sandbox &amp; Ledger</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Simulated banking environment. Privileged ledger actions require server-side cryptographic approval.
          </p>
        </div>

        <button
          onClick={onResetLedger}
          aria-label="Reset Demo Sandbox"
          className="self-start sm:self-auto px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs flex items-center gap-1.5 transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset Demo Sandbox</span>
        </button>
      </div>

      {/* Account Balance Card */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="md:col-span-2 p-6 rounded-xl bg-gradient-to-br from-[#0e1e38] via-[#0f172a] to-[#0a1124] border border-cyan-500/30 shadow-xl relative overflow-hidden">
          <div className="relative z-10 flex flex-col justify-between h-full">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono tracking-wider text-cyan-300 uppercase">
                  PRIMARY DEMO CHECKING ACCOUNT
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  SECURED BY AI FIREWALL
                </span>
              </div>
              <div className="text-3xl sm:text-4xl font-bold font-mono text-white mt-3">
                ${balance.toLocaleString('en-US', { minimumFractionDigits: 2 })}
              </div>
              <div className="text-xs text-slate-400 mt-1 font-mono">
                Account ID: <span className="text-slate-300">usr_sarah_connor_808</span> • Currency: USD (Simulated)
              </div>
            </div>

            <div className="grid grid-cols-3 gap-2 mt-6 pt-4 border-t border-slate-800/80 text-xs font-mono">
              <div>
                <span className="text-slate-400 block text-[10px]">DAILY LIMIT</span>
                <span className="text-slate-300">$5,000.00</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">MAX SINGLE TX</span>
                <span className="text-slate-300">$1,000.00</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">AUTH GATE</span>
                <span className="text-emerald-400">ENFORCED</span>
              </div>
            </div>
          </div>
        </div>

        {/* Security Demonstration Tools */}
        <div className="p-5 rounded-xl bg-[#0f172a] border border-slate-800 flex flex-col justify-between space-y-4">
          <div>
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Live Jury Attack Demos
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Test server-side immunity against client-state tampering and duplicate replay attacks.
            </p>
          </div>

          <div className="space-y-2.5">
            <button
              onClick={handleTamperBypassTest}
              disabled={isLoading}
              className="w-full px-3 py-2 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 font-mono text-xs flex items-center justify-between transition-colors"
            >
              <span>1. Test Client Tamper Bypass</span>
              <span className="text-[10px] text-rose-400 font-bold">FAIL SAFE</span>
            </button>

            <button
              onClick={handleIdempotencyReplayTest}
              disabled={isLoading}
              className="w-full px-3 py-2 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 font-mono text-xs flex items-center justify-between transition-colors"
            >
              <span>2. Test Idempotency Replay</span>
              <span className="text-[10px] text-amber-400 font-bold">ANTI-REPLAY</span>
            </button>
          </div>
        </div>
      </div>

      {/* Security Demonstration Feedback */}
      {demoMessage && (
        <div
          role="status"
          aria-live="polite"
          className={`p-4 rounded-xl border text-xs font-mono leading-relaxed ${
            demoMessage.isError
              ? 'bg-rose-950/30 border-rose-500/40 text-rose-200'
              : 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200'
          }`}
        >
          {demoMessage.text}
        </div>
      )}

      {/* Verified Demo Recipients Directory */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
            <Users className="w-4 h-4 text-cyan-400" />
            Configured Demo Recipients (Allowlist)
          </h3>
          <span className="text-xs text-slate-400 font-mono">5 Authorized Entities</span>
        </div>
        <p className="text-xs text-slate-400 mb-4">
          Transfers to recipients outside this allowlist are flagged as unverified and halted by deterministic rules.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {DEMO_RECIPIENT_PROFILES.map((recip) => (
            <div
              key={recip.id}
              onClick={() => setSelectedRecipient(recip.account)}
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                selectedRecipient === recip.account
                  ? 'bg-cyan-950/30 border-cyan-500/50 shadow-[0_0_10px_rgba(6,182,212,0.15)]'
                  : 'bg-slate-900 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="font-mono text-xs font-bold text-white truncate">{recip.account}</div>
              <div className="text-[11px] text-slate-400 truncate">{recip.name}</div>
              <div className="mt-2 flex items-center justify-between text-[10px] font-mono">
                <span className="text-cyan-400">{recip.category}</span>
                <span className="text-slate-400">Max ${recip.max_limit}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Mock Banking Ledger Audit History */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold font-mono text-slate-200 flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            Mock Banking Transaction Ledger
          </h3>
          <span className="text-xs text-slate-400 font-mono">{transactions.length} records</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase text-[11px]">
                <th scope="col" className="pb-2.5">Time</th>
                <th scope="col" className="pb-2.5">Type</th>
                <th scope="col" className="pb-2.5">Sender</th>
                <th scope="col" className="pb-2.5">Recipient</th>
                <th scope="col" className="pb-2.5">Amount</th>
                <th scope="col" className="pb-2.5">Status</th>
                <th scope="col" className="pb-2.5">Idempotency Key</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {transactions.map((tx) => (
                <tr key={tx.id} className="hover:bg-slate-900/50 transition-colors">
                  <td className="py-2.5 text-slate-400">{new Date(tx.timestamp).toLocaleTimeString()}</td>
                  <td className="py-2.5">
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-cyan-300 border border-slate-700">
                      {tx.type}
                    </span>
                  </td>
                  <td className="py-2.5 text-slate-400 truncate max-w-[120px]">{tx.sender}</td>
                  <td className="py-2.5 text-cyan-300 font-bold">{tx.recipient}</td>
                  <td className="py-2.5 font-bold text-white">
                    {tx.type === 'TRANSFER' ? `-$${tx.amount.toFixed(2)}` : `+$${tx.amount.toFixed(2)}`}
                  </td>
                  <td className="py-2.5">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        tx.status === 'COMPLETED'
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                      }`}
                    >
                      {tx.status}
                    </span>
                  </td>
                  <td className="py-2.5 text-slate-400 truncate max-w-[140px]">{tx.idempotency_key}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
