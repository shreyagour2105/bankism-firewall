/**
 * BANKISM Threat Scanner
 * Transparent heuristic threat detection, context-aware syntax scanning,
 * and pattern analysis for AI prompts, memos, and parameters.
 */

import { ThreatCategory, RiskLevel, BankingIntent, ExtractedParameters } from '../types/firewall';
import { NormalizationResult } from './normalizer';

export interface ThreatScanResult {
  threats: ThreatCategory[];
  risk_level: RiskLevel;
  detected_patterns: string[];
  intent: BankingIntent;
  extracted_params: ExtractedParameters;
  is_quoted_suspicious_text: boolean;
  notes: string[];
}

// Configured Demo Recipients Allowlist
export const DEMO_RECIPIENTS = [
  'alice.eth',
  'bob_miller',
  'carol_tech',
  'david_chen',
  'elena_finance',
];

// Prompt Injection Signatures
const PROMPT_INJECTION_PATTERNS = [
  /\bignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|commands|directives)\b/i,
  /\bdisregard\s+(all\s+)?(previous|prior|system|security)\s+(rules|instructions|prompts|policies)\b/i,
  /\bforget\s+(all\s+)?(prior|previous|existing)\s+(guidelines|instructions|rules|safety)\b/i,
  /\bnew\s+(system\s+)?instructions\s*:\s*/i,
  /\boverride\s+(all\s+)?(security|system|safety|firewall)\s+(protocols|rules|policies)\b/i,
  /\badmin\s+command\s*:\s*/i,
  /\bsystem\s+override\s+code\b/i,
  /\bexecute\s+as\s+root\b/i,
  /\bdo\s+not\s+follow\s+any\s+restrictions\b/i,
];

// Roleplay & Jailbreak Signatures
const JAILBREAK_PATTERNS = [
  /\bpretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(unrestricted|evil|unfiltered|jailbroken|dan)\b/i,
  /\bact\s+as\s+(an?\s+)?(unrestricted|rogue|jailbroken|free)\b/i,
  /\bact\s+as\s+a\s+bank\s+teller\s+with\s+no\s+(restrictions|limits|rules)\b/i,
  /\bdeveloper\s+mode\s+(enabled|activated|on)\b/i,
  /\byou\s+are\s+now\s+in\s+developer\s+mode\b/i,
  /\bjailbreak\s+mode\b/i,
  /\bDAN\s+mode\b/i,
  /\bhypothetical\s+scenario\s+where\s+(you\s+must|rules\s+don't\s+apply)\b/i,
  /\bfor\s+testing\s+purposes\s+only\s*,\s*(bypass|ignore)\b/i,
];

// Policy Override Signatures
const POLICY_OVERRIDE_PATTERNS = [
  /\bdisable\s+(transaction\s+)?(limits?|verification|security|safeguards?)\b/i,
  /\bset\s+(my\s+)?balance\s+to\s+(infinity|\$?[0-9]{7,}|unlimited)\b/i,
  /\bbypass\s+(authorization|authentication|2fa|approval|checks?)\b/i,
  /\bskip\s+(security|policy|limit)\s+check(s)?\b/i,
  /\bsecurity_check\s*=\s*(false|0|disabled)\b/i,
  /\blimit_override\s*=\s*true\b/i,
];

// Data Exfiltration & System Leakage Signatures
const DATA_EXFILTRATION_PATTERNS = [
  /\b(reveal|show|print|display|tell\s+me|dump|leak)\s+(the\s+)?(system\s+prompt|initial\s+instructions|secret\s+keys?|api\s+keys?|credentials?)\b/i,
  /\b(dump|export|extract|list)\s+(all\s+)?(user\s+accounts?|database\s+records?|private\s+ledger|customer\s+data)\b/i,
  /\bwhat\s+(is|are)\s+your\s+(secret|internal|system)\s+(instructions|prompt|rules)\b/i,
  /\bgive\s+me\s+your\s+api\s+key\b/i,
  /\bwhat\s+is\s+the\s+root\s+password\b/i,
];

// Malicious Memo & SQLi Signatures
const SQLI_PATTERNS = [
  /(?:'|--|\bOR\b|\bAND\b).*(?:UNION\s+SELECT|DROP\s+TABLE|ALTER\s+TABLE|DELETE\s+FROM|INSERT\s+INTO)/i,
  /;\s*(?:DROP|DELETE|UPDATE|TRUNCATE|INSERT)\s+/i,
  /'\s*OR\s*'1'\s*=\s*'1/i,
  /"\s*OR\s*"1"\s*=\s*"1/i,
];

const MEMO_INJECTION_PATTERNS = [
  /\btransfer\s+\$?[0-9]+\s+to\b/i,
  /\bignore\s+(limit|rules|instructions)\b/i,
  /\bexecute\s+payload\b/i,
  /\bsend\s+all\s+funds\b/i,
  /\boverride\s+recipient\b/i,
];

/**
 * Check if suspicious text is purely within quotation marks in a benign meta-context
 * e.g., The customer inquiry said: "ignore all previous instructions" - please check my balance.
 */
function inspectQuotedContext(raw: string): { isQuoted: boolean; benignOuterIntent: boolean } {
  // Extract quoted strings
  const quoteRegex = /["'“]([^"'”]{5,})["'”]/g;
  let match;
  let hasSuspiciousQuote = false;

  while ((match = quoteRegex.exec(raw)) !== null) {
    const quotedContent = match[1].toLowerCase();
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
      if (pattern.test(quotedContent)) {
        hasSuspiciousQuote = true;
        break;
      }
    }
  }

  if (!hasSuspiciousQuote) {
    return { isQuoted: false, benignOuterIntent: false };
  }

  // Remove the quotes and see if the outer request is asking a harmless question
  const outerText = raw.replace(quoteRegex, '').toLowerCase();
  const isOuterHarmless =
    /\b(check|what\s+is|show|view|tell\s+me)\s+(?:my\s+)?(?:current\s+|available\s+)?(balance|funds|account)\b/i.test(outerText) ||
    /\b(reported|ticket|customer|client|user|inquiry|feedback|log|query|email|said|notes?)\b/i.test(outerText);

  return {
    isQuoted: true,
    benignOuterIntent: isOuterHarmless,
  };
}

/**
 * Parse natural language for intent, amount, and recipient
 */
export function extractIntentAndParams(
  text: string,
  explicitParams?: { recipient?: string; amount?: number; memo?: string }
): {
  intent: BankingIntent;
  params: ExtractedParameters;
  ambiguities: string[];
} {
  const ambiguities: string[] = [];
  const lower = text.toLowerCase();

  // Explicit parameters take precedence if provided, but still check for conflicts
  let recipient = explicitParams?.recipient?.trim();
  let amount = explicitParams?.amount;
  let memo = explicitParams?.memo?.trim();

  // 1. Detect Intent
  let intent: BankingIntent = 'UNKNOWN';

  const isBalanceQuery =
    /\b(balance|how\s+much\s+(money|funds|cash)|check\s+(my\s+)?account|available\s+funds)\b/i.test(lower);
  const isTransferQuery =
    /\b(transfer|send|wire|pay|move\s+money|remit)\b/i.test(lower);

  if (isBalanceQuery && !isTransferQuery) {
    intent = 'BALANCE_INQUIRY';
  } else if (isTransferQuery) {
    intent = 'TRANSFER';
  } else if (explicitParams?.recipient || explicitParams?.amount) {
    intent = 'TRANSFER';
  } else if (isBalanceQuery) {
    intent = 'BALANCE_INQUIRY';
  } else {
    intent = 'OTHER';
  }

  // 2. Extract Amount from text if not explicitly provided
  if (amount === undefined) {
    const amountMatches = text.match(/\$\s*([0-9]+(?:\.[0-9]{1,2})?)|([0-9]+(?:\.[0-9]{1,2})?)\s*(?:dollars|usd)/gi);
    const plainNumMatches = text.match(/\b(?:transfer|send|wire|pay)\s+([0-9]+(?:\.[0-9]{1,2})?)\b/i);

    if (amountMatches && amountMatches.length > 1) {
      ambiguities.push(`Multiple conflicting amounts detected in request: ${amountMatches.join(', ')}.`);
    }

    if (amountMatches && amountMatches.length > 0) {
      const cleanedNum = amountMatches[0].replace(/[^0-9.]/g, '');
      const parsed = parseFloat(cleanedNum);
      if (!isNaN(parsed)) amount = parsed;
    } else if (plainNumMatches && plainNumMatches[1]) {
      const parsed = parseFloat(plainNumMatches[1]);
      if (!isNaN(parsed)) amount = parsed;
    }
  }

  // Check if multiple conflicting amounts exist in phrasing like "send 100 or make it 200"
  const alternativeAmountPattern = /\b([0-9]+(?:\.[0-9]{2})?)\s*(?:or|instead\s+of|rather\s+than)\s*([0-9]+(?:\.[0-9]{2})?)\b/i;
  if (alternativeAmountPattern.test(text)) {
    ambiguities.push('Conflicting alternative amounts specified in request.');
  }

  // 3. Extract Recipient from text if not explicitly provided
  if (!recipient) {
    // Check known demo recipients first
    const foundRecipients: string[] = [];
    for (const demoRecip of DEMO_RECIPIENTS) {
      if (lower.includes(demoRecip.toLowerCase())) {
        foundRecipients.push(demoRecip);
      }
    }

    // Pattern for "to [name]"
    const toMatches = text.match(/\b(?:to|recipient:?)\s+([a-zA-Z0-9_.-]+)/gi);
    if (toMatches) {
      for (const m of toMatches) {
        const candidate = m.replace(/^(?:to|recipient:?)\s+/i, '').trim();
        if (candidate && !['the', 'my', 'account', 'a', 'his', 'her', 'their'].includes(candidate.toLowerCase())) {
          if (!foundRecipients.includes(candidate)) {
            foundRecipients.push(candidate);
          }
        }
      }
    }

    if (foundRecipients.length > 1) {
      ambiguities.push(`Multiple distinct recipients detected in instruction: ${foundRecipients.join(' and ')}.`);
    }

    if (foundRecipients.length > 0) {
      recipient = foundRecipients[0];
    }
  }

  // 4. Extract Memo if phrased like "for dinner" or "memo: ..."
  if (!memo) {
    const memoMatch = text.match(/\b(?:for|memo:?|note:?)\s+["']?([^"'\n,.]+)["']?/i);
    if (memoMatch && memoMatch[1]) {
      memo = memoMatch[1].trim();
    }
  }

  return {
    intent,
    params: {
      recipient,
      amount,
      memo,
    },
    ambiguities,
  };
}

/**
 * Scan normalized input for security threats and policy risks
 */
export function scanForThreats(
  norm: NormalizationResult,
  explicitParams?: { recipient?: string; amount?: number; memo?: string }
): ThreatScanResult {
  const threats: ThreatCategory[] = [];
  const detectedPatterns: string[] = [];
  const notes: string[] = [];
  let riskLevel: RiskLevel = 'LOW';

  const deobfuscated = norm.deobfuscated_for_analysis;
  const rawOriginal = norm.original;

  // 1. Obfuscation Check
  if (norm.obfuscation_detected) {
    threats.push('OBFUSCATION');
    detectedPatterns.push(...norm.obfuscation_details);
    if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
  }

  // 2. Check for Quoted Context (Test 15)
  const quotedContext = inspectQuotedContext(rawOriginal);
  let isQuotedSuspicious = false;

  if (quotedContext.isQuoted && quotedContext.benignOuterIntent) {
    isQuotedSuspicious = true;
    notes.push('Suspicious phrase is safely enclosed in quotation marks inside a benign meta-inquiry.');
    // Do not automatically mark CRITICAL prompt injection if it is purely quoted in a harmless inquiry
  }

  // 3. Prompt Injection Scan
  let directInjectionFound = false;
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(deobfuscated)) {
      directInjectionFound = true;
      detectedPatterns.push(`Prompt Injection pattern detected: ${pattern.toString()}`);
      break;
    }
  }

  if (directInjectionFound) {
    if (isQuotedSuspicious) {
      // Benign inquiry quoting suspicious text
      riskLevel = 'LOW';
      notes.push('Quoted trigger evaluated in harmless context. Request handled as benign inquiry.');
    } else {
      threats.push('PROMPT_INJECTION');
      riskLevel = 'CRITICAL';
    }
  }

  // 4. Jailbreak & Roleplay Scan
  for (const pattern of JAILBREAK_PATTERNS) {
    if (pattern.test(deobfuscated)) {
      threats.push('JAILBREAK');
      detectedPatterns.push(`Jailbreak/Roleplay signature detected: ${pattern.toString()}`);
      riskLevel = 'CRITICAL';
      break;
    }
  }

  // 5. Policy Override Scan
  for (const pattern of POLICY_OVERRIDE_PATTERNS) {
    if (pattern.test(deobfuscated)) {
      threats.push('POLICY_OVERRIDE');
      detectedPatterns.push(`System policy override attempt detected: ${pattern.toString()}`);
      riskLevel = 'CRITICAL';
      break;
    }
  }

  // 6. Data Exfiltration Scan
  for (const pattern of DATA_EXFILTRATION_PATTERNS) {
    if (pattern.test(deobfuscated)) {
      threats.push('DATA_EXFILTRATION');
      detectedPatterns.push(`Sensitive data exfiltration request: ${pattern.toString()}`);
      if (riskLevel !== 'CRITICAL') riskLevel = 'HIGH';
      break;
    }
  }

  // 7. Memo Inspection (Check both input text and explicit memo field)
  const memoToCheck = [explicitParams?.memo, deobfuscated].filter(Boolean).join(' ');
  let memoThreatFound = false;

  for (const sqli of SQLI_PATTERNS) {
    if (sqli.test(memoToCheck)) {
      memoThreatFound = true;
      detectedPatterns.push(`SQL Injection attempt in memo: ${sqli.toString()}`);
      break;
    }
  }

  if (explicitParams?.memo) {
    for (const memoInj of MEMO_INJECTION_PATTERNS) {
      if (memoInj.test(explicitParams.memo)) {
        memoThreatFound = true;
        detectedPatterns.push(`Embedded unauthorized transaction instruction in memo.`);
        break;
      }
    }
  }

  if (memoThreatFound) {
    threats.push('MALICIOUS_MEMO');
    riskLevel = 'CRITICAL';
  }

  // 8. Extract Intent and Parameters
  const { intent, params, ambiguities } = extractIntentAndParams(rawOriginal, explicitParams);

  // 9. Ambiguity and Conflict Checks
  if (ambiguities.length > 0) {
    threats.push('AMBIGUOUS_REQUEST');
    detectedPatterns.push(...ambiguities);
    if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
  }

  // If threats list is empty, mark NONE
  if (threats.length === 0) {
    threats.push('NONE');
  }

  return {
    threats,
    risk_level: riskLevel,
    detected_patterns: detectedPatterns,
    intent,
    extracted_params: params,
    is_quoted_suspicious_text: isQuotedSuspicious,
    notes,
  };
}
