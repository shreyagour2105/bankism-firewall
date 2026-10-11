/**
 * BANKISM — AI Firewall & Guardrail Defense
 * Core Type Definitions & Verdict Schemas
 */

export type Verdict = 'APPROVED' | 'BLOCKED' | 'REVIEW_REQUIRED';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatCategory =
  | 'NONE'
  | 'PROMPT_INJECTION'
  | 'JAILBREAK'
  | 'POLICY_OVERRIDE'
  | 'MALICIOUS_MEMO'
  | 'OBFUSCATION'
  | 'DATA_EXFILTRATION'
  | 'AMBIGUOUS_REQUEST'
  | 'INVALID_TRANSACTION'
  | 'ANALYSIS_FAILURE';

export type BankingIntent = 'BALANCE_INQUIRY' | 'TRANSFER' | 'TRANSACTION_HISTORY' | 'OTHER' | 'UNKNOWN';

export interface PolicyChecks {
  schema_valid: boolean;
  input_normalised: boolean;
  threat_scan_passed: boolean;
  policy_passed: boolean;
  recipient_valid: boolean;
  amount_valid: boolean;
}

export interface ExtractedParameters {
  recipient?: string;
  amount?: number;
  memo?: string;
}

export type EngineMode = 'DETERMINISTIC_RULES' | 'HYBRID_LLM_ADVISORY' | 'FAIL_CLOSED';

export interface FirewallVerdict {
  request_id: string;
  timestamp: string;
  verdict: Verdict;
  risk_level: RiskLevel;
  threat_category: ThreatCategory[];
  intent: BankingIntent;
  rationale: string;
  normalised_request: string;
  extracted_parameters?: ExtractedParameters;
  requires_confirmation: boolean;
  transaction_executed: boolean;
  execution_error?: string;
  checks: PolicyChecks;
  engine_mode: EngineMode;
  latency_ms: number;
}

export interface AnalyzeRequestPayload {
  raw_input: string;
  recipient?: string;
  amount?: number;
  memo?: string;
  idempotency_key?: string;
}

export interface ExecuteTransferPayload {
  request_id: string;
  recipient: string;
  amount: number;
  memo?: string;
  idempotency_key: string;
  // Security token or cryptographic signature representing server approval
  verdict_token: string;
}

export interface MockTransaction {
  id: string;
  timestamp: string;
  type: 'TRANSFER' | 'CREDIT' | 'BALANCE_CHECK';
  sender: string;
  recipient: string;
  amount: number;
  memo?: string;
  status: 'COMPLETED' | 'REJECTED' | 'FLAGGED';
  idempotency_key: string;
  request_id: string;
}

export interface DemoRecipient {
  id: string;
  name: string;
  account: string;
  category: 'VERIFIED_PEER' | 'MERCHANT' | 'UTILITY';
  max_limit: number;
}
