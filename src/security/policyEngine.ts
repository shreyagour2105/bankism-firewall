/**
 * BANKISM Deterministic Policy Engine
 * Immutable security rules, fail-closed boundaries, and final verdict arbitration.
 * The AI model is strictly an advisory analyzer; this engine is the SOLE authority.
 */

import {
  FirewallVerdict,
  Verdict,
  RiskLevel,
  ThreatCategory,
  PolicyChecks,
  AnalyzeRequestPayload,
  EngineMode,
} from '../types/firewall';
import { normaliseInput } from './normalizer';
import { scanForThreats, DEMO_RECIPIENTS } from './threatScanner';

export const CONFIG = {
  MAX_SINGLE_TRANSFER_USD: 1000.0,
  DEMO_ACCOUNT_INITIAL_BALANCE: 5000.0,
  DEMO_ACCOUNT_OWNER: 'usr_sarah_connor_808',
  FAIL_CLOSED_TIMEOUT_MS: 3000,
};

/**
 * Generate a unique cryptographic-like request ID
 */
export function generateRequestId(): string {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 9);
  return `req_bkm_${ts}_${rand}`;
}

/**
 * Deterministic Evaluation Pipeline:
 * Input -> Normalization -> Threat Scan -> Deterministic Policy Validation -> Structured Verdict
 */
export function evaluateSecurityPolicy(
  payload: AnalyzeRequestPayload,
  llmAdvisory?: {
    suggested_risk?: RiskLevel;
    suggested_threats?: ThreatCategory[];
    notes?: string;
  },
  engineMode: EngineMode = 'DETERMINISTIC_RULES'
): FirewallVerdict {
  const startTime = Date.now();
  const requestId = generateRequestId();
  const rawInput = payload.raw_input || '';

  // 1. Input Normalisation Check
  const norm = normaliseInput(rawInput);
  const inputNormalised = true;

  // 2. Threat & Intent Scanning
  const threatResult = scanForThreats(norm, {
    recipient: payload.recipient,
    amount: payload.amount,
    memo: payload.memo,
  });

  const threats = new Set<ThreatCategory>(threatResult.threats);
  let riskLevel: RiskLevel = threatResult.risk_level;
  const rationaleParts: string[] = [];

  // Include specific detected ambiguity / conflict patterns in rationale
  for (const pat of threatResult.detected_patterns) {
    if (pat.startsWith('Conflicting') || pat.startsWith('Multiple')) {
      rationaleParts.push(pat);
    }
  }

  // Ingest optional advisory LLM insights with zero trust (never blindly adopt approval)
  if (llmAdvisory?.suggested_threats) {
    for (const t of llmAdvisory.suggested_threats) {
      if (t !== 'NONE') {
        threats.add(t);
        rationaleParts.push(`Advisory AI flagged threat category: ${t}`);
      }
    }
  }

  // 3. Evaluate Individual Policy Checks
  const checks: PolicyChecks = {
    schema_valid: Boolean(rawInput.trim().length > 0),
    input_normalised: inputNormalised,
    threat_scan_passed: false,
    policy_passed: false,
    recipient_valid: false,
    amount_valid: false,
  };

  const intent = threatResult.intent;
  const extracted = threatResult.extracted_params;
  const amount = extracted.amount;
  const recipient = extracted.recipient;

  // Check Critical Threat Categories
  const hasCriticalThreat =
    threats.has('PROMPT_INJECTION') ||
    threats.has('JAILBREAK') ||
    threats.has('POLICY_OVERRIDE') ||
    threats.has('MALICIOUS_MEMO');

  const hasDataExfil = threats.has('DATA_EXFILTRATION');
  const hasObfuscation = threats.has('OBFUSCATION');
  const hasAmbiguity = threats.has('AMBIGUOUS_REQUEST');

  if (threatResult.is_quoted_suspicious_text) {
    rationaleParts.push('Evaluated suspicious keyword inside quoted text; harmless outer inquiry preserved.');
  }

  // Evaluate Amount Validity
  if (amount !== undefined) {
    if (!Number.isFinite(amount) || isNaN(amount) || amount < 0) {
      checks.amount_valid = false;
      threats.add('INVALID_TRANSACTION');
      rationaleParts.push('Transfer amount must be a finite, positive numerical value.');
    } else if (amount === 0) {
      checks.amount_valid = false;
      threats.add('INVALID_TRANSACTION');
      rationaleParts.push('Transfer amount cannot be zero.');
    } else if (amount > CONFIG.MAX_SINGLE_TRANSFER_USD) {
      checks.amount_valid = false;
      threats.add('INVALID_TRANSACTION');
      rationaleParts.push(`Transfer amount ($${amount}) exceeds maximum demo safety limit of $${CONFIG.MAX_SINGLE_TRANSFER_USD}.`);
    } else {
      checks.amount_valid = true;
    }
  } else if (intent === 'TRANSFER') {
    checks.amount_valid = false;
    threats.add('AMBIGUOUS_REQUEST');
    rationaleParts.push('Transfer request did not specify a valid monetary amount.');
  } else if (intent === 'BALANCE_INQUIRY' || intent === 'TRANSACTION_HISTORY') {
    // Read-only queries do not require a monetary amount
    checks.amount_valid = true;
  } else {
    // Unknown or other intents must never default amount to valid
    checks.amount_valid = false;
  }

  // Evaluate Recipient Validity
  if (recipient) {
    const isKnown = DEMO_RECIPIENTS.includes(recipient);
    if (isKnown) {
      checks.recipient_valid = true;
    } else {
      checks.recipient_valid = false;
      threats.add('INVALID_TRANSACTION');
      rationaleParts.push(`Recipient "${recipient}" is not in the authorized demo peer directory.`);
    }
  } else if (intent === 'TRANSFER') {
    checks.recipient_valid = false;
    threats.add('AMBIGUOUS_REQUEST');
    rationaleParts.push('Transfer request must specify an authorized recipient.');
  } else if (intent === 'BALANCE_INQUIRY' || intent === 'TRANSACTION_HISTORY') {
    // Read-only queries do not require a recipient
    checks.recipient_valid = true;
  } else {
    // Unknown or other intents must never default recipient to valid
    checks.recipient_valid = false;
  }

  // Remove NONE if active threats exist
  if (threats.size > 1 && threats.has('NONE')) {
    threats.delete('NONE');
  }

  // Threat Scan Passed if no security attack threats are active
  const hasAttackThreat =
    hasCriticalThreat ||
    hasDataExfil ||
    (hasObfuscation && hasCriticalThreat);

  checks.threat_scan_passed = !hasAttackThreat;

  // 4. Arbitrate Final Verdict & Risk Level
  let verdict: Verdict = 'BLOCKED';

  if (hasCriticalThreat) {
    verdict = 'BLOCKED';
    riskLevel = 'CRITICAL';
    checks.policy_passed = false;
    rationaleParts.unshift('BLOCKED: Request triggered critical AI security guardrails (injection/jailbreak/override).');
  } else if (hasDataExfil) {
    verdict = 'BLOCKED';
    riskLevel = 'HIGH';
    checks.policy_passed = false;
    rationaleParts.unshift('BLOCKED: Request attempted unauthorized extraction of system prompts or sensitive data.');
  } else if (amount !== undefined && (!Number.isFinite(amount) || isNaN(amount) || amount < 0)) {
    verdict = 'BLOCKED';
    riskLevel = 'HIGH';
    checks.policy_passed = false;
    rationaleParts.unshift('BLOCKED: Negative or non-finite transaction amount rejected by deterministic gate.');
  } else if (amount === 0) {
    verdict = 'REVIEW_REQUIRED';
    riskLevel = 'MEDIUM';
    checks.policy_passed = false;
    rationaleParts.unshift('REVIEW_REQUIRED: Transfer amount cannot be zero.');
  } else if (hasAmbiguity || threats.has('AMBIGUOUS_REQUEST') || threats.has('INVALID_TRANSACTION')) {
    verdict = 'REVIEW_REQUIRED';
    if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
    checks.policy_passed = false;
    rationaleParts.unshift('REVIEW_REQUIRED: Request contains ambiguous parameters, unsupported recipient, or policy boundary.');
  } else if (intent === 'BALANCE_INQUIRY') {
    verdict = 'APPROVED';
    riskLevel = 'LOW';
    checks.policy_passed = true;
    checks.threat_scan_passed = true;
    rationaleParts.unshift('APPROVED: Benign balance inquiry verified against all deterministic security checks.');
  } else if (intent === 'TRANSACTION_HISTORY') {
    verdict = 'APPROVED';
    riskLevel = 'LOW';
    checks.policy_passed = true;
    checks.threat_scan_passed = true;
    rationaleParts.unshift('APPROVED: Read-only transaction history inquiry verified against all deterministic security checks.');
  } else if (intent === 'TRANSFER') {
    if (checks.recipient_valid && checks.amount_valid && checks.threat_scan_passed) {
      verdict = 'APPROVED';
      riskLevel = 'LOW';
      checks.policy_passed = true;
      rationaleParts.unshift(`APPROVED: Transfer of $${amount} to "${recipient}" cleared all deterministic firewall rules.`);
    } else {
      verdict = 'REVIEW_REQUIRED';
      checks.policy_passed = false;
      if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
    }
  } else {
    // Unknown or other intent - fail closed
    verdict = 'REVIEW_REQUIRED';
    riskLevel = 'MEDIUM';
    checks.policy_passed = false;
    checks.recipient_valid = false;
    checks.amount_valid = false;
    rationaleParts.unshift('REVIEW_REQUIRED: Intent could not be mapped to an authorized banking action.');
  }

  // Clean threat categories array
  const threatCategoriesList = Array.from(threats);

  const latencyMs = Date.now() - startTime;

  return {
    request_id: requestId,
    timestamp: new Date().toISOString(),
    verdict,
    risk_level: riskLevel,
    threat_category: threatCategoriesList,
    intent,
    rationale: rationaleParts.join(' '),
    normalised_request: norm.normalised,
    extracted_parameters: extracted,
    requires_confirmation: verdict === 'APPROVED' && intent === 'TRANSFER',
    transaction_executed: false,
    checks,
    engine_mode: engineMode,
    latency_ms: latencyMs,
  };
}

/**
 * Fail-Closed Safe Fallback Verdict
 * Used when network times out, JSON is malformed, or AI service errors.
 */
export function createFailClosedVerdict(
  reason: string,
  rawInput: string = ''
): FirewallVerdict {
  return {
    request_id: generateRequestId(),
    timestamp: new Date().toISOString(),
    verdict: 'BLOCKED',
    risk_level: 'HIGH',
    threat_category: ['ANALYSIS_FAILURE'],
    intent: 'UNKNOWN',
    rationale: `FAIL-CLOSED ACTIVATED: Analysis service could not securely verify request (${reason}). Privileged execution halted.`,
    normalised_request: rawInput,
    requires_confirmation: false,
    transaction_executed: false,
    checks: {
      schema_valid: false,
      input_normalised: false,
      threat_scan_passed: false,
      policy_passed: false,
      recipient_valid: false,
      amount_valid: false,
    },
    engine_mode: 'FAIL_CLOSED',
    latency_ms: 0,
  };
}
