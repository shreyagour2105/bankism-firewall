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
  'DEMO001',
  'DEMO002',
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

// Data Exfiltration & Credential / Secret Extraction Signatures
const DATA_EXFILTRATION_PATTERNS = [
  // Direct exfiltration verbs targeting keys, tokens, credentials, secrets
  /\b(reveal|show|print|display|tell(?:\s+me)?|dump|leak|extract|give(?:\s+me)?|provide|expose|share|output|read|unveil)\s+(?:the\s+|your\s+|all\s+|system\s+|any\s+|our\s+)?(?:secret\s+|signing\s+|admin\s+|api\s+|private\s+|auth(?:orization)?\s+|root\s+|encryption\s+)?(?:keys?|tokens?|passwords?|credentials?|secrets?)\b/i,

  // Multi-word phrases targeting signing keys, admin tokens, credentials anywhere after an extraction verb
  /\b(reveal|show|print|display|tell(?:\s+me)?|dump|leak|extract|give(?:\s+me)?|provide|expose|share|output)\s+.*?\b(signing\s+key|admin\s+token|admin_token|signing_key|firewall_signing_key|admin_reset_token|secret\s+key|api\s+key|private\s+key|credentials?|root\s+password)\b/i,

  // Extraction of system instructions, security rules, prompts (including hidden/internal)
  /\b(reveal|show|print|display|tell(?:\s+me)?|dump|leak|extract|give(?:\s+me)?|provide|expose|share|output)\s+.*?\b(system\s+prompt|initial\s+instructions|system\s+instructions|security\s+instructions|hidden\s+(?:system\s+|security\s+)?instructions?|internal\s+instructions?|internal\s+rules?)\b/i,

  // Questions probing for secrets, keys, tokens, or hidden instructions
  /\bwhat\s+(?:is|are)\s+(?:the|your)\s+(?:secret|signing|admin|api|private|root|system|hidden|internal)\s+(?:key|token|password|credential|secret|prompt|instruction)s?\b/i,
  /\b(dump|export|extract|list)\s+(all\s+)?(user\s+accounts?|database\s+records?|private\s+ledger|customer\s+data)\b/i,
  /\bgive\s+me\s+your\s+(api\s+key|signing\s+key|admin\s+token|secret|password)\b/i,
  /\bwhat\s+is\s+the\s+(root\s+password|signing\s+key|admin\s+token|secret\s+key)\b/i,
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

  const isHistoryQuery =
    /\b(last\s+\d+\s+transactions?|transaction\s+history|recent\s+transactions?|past\s+transactions?|show\s+(?:my\s+)?(?:last\s+\d+\s+)?transactions?|account\s+history|statement)\b/i.test(lower);
  const isBalanceQuery =
    /\b(balance|how\s+much\s+(?:money|funds|cash)|check\s+(?:my\s+)?account|available\s+funds)\b/i.test(lower);
  const isTransferQuery =
    /\b(transfer|send|wire|pay|move\s+money|remit)\b/i.test(lower);

  if (isTransferQuery) {
    intent = 'TRANSFER';
  } else if (explicitParams?.recipient || explicitParams?.amount !== undefined) {
    intent = 'TRANSFER';
  } else if (isHistoryQuery) {
    intent = 'TRANSACTION_HISTORY';
  } else if (isBalanceQuery) {
    intent = 'BALANCE_INQUIRY';
  } else {
    intent = 'OTHER';
  }

  // 1. Explicitly detect and reject negative monetary syntax (e.g. -$100, $-100, - ₹500, -100 dollars, transfer -100)
  const negativeMonetaryPattern = /(?:-\s*[\$₹€£]|[\$₹€£]\s*-|-\s*(?:rs\.?|inr|usd|eur|gbp)(?:\b(?!\.)|\s)|(?:rs\.?|inr|usd|eur|gbp)\s*-|-\s*[0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?\s*(?:[\$₹€£]|dollars?|rupees?|inr|usd|eur|gbp|cents?\b)|\b(?:transfer|send|wire|pay)\s+-\s*[0-9]+)/i;
  const hasNegativeMonetarySyntax = negativeMonetaryPattern.test(text);
  if (hasNegativeMonetarySyntax) {
    ambiguities.push('Negative monetary amount syntax detected. Transfers cannot have negative amounts.');
  }

  // 2. Validate complete monetary token (e.g. reject $500abc, 500abc dollars, ₹100xyz, -$500foo)
  // Ensures invalid non-numeric/alphabetic suffix attached to a currency amount fails closed
  const malformedAmountPattern = /(?:-?\s*[\$₹€£]|-?\s*(?:rs\.?|inr|usd|eur|gbp)(?:\b(?!\.)|\s))\s*-?[0-9]+(?:,[0-9]+)*(?:\.[0-9]+)?[a-zA-Z_]+|-?[0-9]+(?:,[0-9]+)*(?:\.[0-9]+)?[a-zA-Z_]+(?:\s*(?:[\$₹€£]|(?:dollars?|rupees?|inr|usd|eur|gbp|cents?)\b))/i;
  const isMalformedAmountToken = malformedAmountPattern.test(text);
  if (isMalformedAmountToken) {
    ambiguities.push('Malformed monetary amount token detected. Amount contains invalid non-numeric suffix or formatting.');
  }

  // Check for ambiguous European decimal notation (comma followed by 1 or 2 digits, e.g. 100,50 or 1.000,50)
  const europeanDecimalPattern = /(?:[\$₹€£]|(?:rs\.?|inr|usd|eur|gbp)(?:\b(?!\.)|\s))?\s*-?[0-9]+(?:[0-9.]*)?,[0-9]{1,2}(?!\d)/i;
  if (europeanDecimalPattern.test(text)) {
    ambiguities.push('Ambiguous European decimal notation detected (comma decimal separator, e.g. 100,50). Please use standard dot notation (e.g. 100.50).');
  }

  // Check for ambiguous Indian numbering comma grouping (2-digit groupings e.g. 1,00,000 Lakhs notation)
  const indianCommaGroupingPattern = /-?[0-9]+(?:,[0-9]{2})+,[0-9]{3}(?:\.[0-9]+)?/;
  if (indianCommaGroupingPattern.test(text)) {
    ambiguities.push('Ambiguous Indian number grouping detected (Lakhs/Crores notation, e.g. 1,00,000). Please specify amount without ambiguous comma grouping.');
  }

  const currencyPrefixRegex = /(?:-?\s*(?:[\$₹€£]|(?:rs\.?|inr|usd|eur|gbp)(?:\b(?!\.)|\s))\s*-?\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?))(?![0-9a-zA-Z_])/gi;
  const currencySuffixRegex = /(-?\s*[0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?)\s*(?:[\$₹€£]|(?:dollars?|rupees?|inr|usd|eur|gbp|cents?)\b)(?![0-9a-zA-Z_])/gi;
  const actionVerbRegex = /\b(?:transfer|send|wire|pay)\s+(?:-?\s*(?:[\$₹€£]|(?:rs\.?|inr|usd|eur|gbp)(?:\b(?!\.)|\s))\s*-?\s*)?(-?\s*[0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?)(?![0-9a-zA-Z_])\b/i;

  const rawExpressionMatches: string[] = [];
  const parsedCandidates: number[] = [];

  const addMatch = (matchStr: string, numGroup?: string) => {
    rawExpressionMatches.push(matchStr.trim());
    const isNegative =
      matchStr.includes('-') ||
      (numGroup ? numGroup.includes('-') : false) ||
      hasNegativeMonetarySyntax;
    const rawDigits = (numGroup || matchStr).replace(/[^0-9.]/g, '');
    if (rawDigits.length > 0) {
      const val = parseFloat(rawDigits);
      if (!isNaN(val)) {
        const finalVal = isNegative ? -Math.abs(val) : val;
        parsedCandidates.push(finalVal);
      }
    }
  };

  let m;
  while ((m = currencyPrefixRegex.exec(text)) !== null) {
    addMatch(m[0], m[1]);
  }
  while ((m = currencySuffixRegex.exec(text)) !== null) {
    addMatch(m[0], m[1]);
  }

  if (rawExpressionMatches.length === 0) {
    const verbMatch = text.match(actionVerbRegex);
    if (verbMatch && verbMatch[1]) {
      addMatch(verbMatch[0], verbMatch[1]);
    }
  }

  // Reject multiple distinct currency expressions even if numeric value is identical (e.g. $100 and ₹100)
  if (rawExpressionMatches.length > 1) {
    ambiguities.push(`Multiple currency expressions detected in request (${rawExpressionMatches.join(', ')}). Single unambiguous transfer amount required.`);
  }

  const uniqueNumericCandidates = Array.from(new Set(parsedCandidates));
  if (uniqueNumericCandidates.length > 1) {
    ambiguities.push(`Multiple conflicting amounts detected in request: ${uniqueNumericCandidates.join(', ')}.`);
  }

  // Check for conflict between explicit parameter and prompt text
  if (explicitParams?.amount !== undefined) {
    if (parsedCandidates.length > 0) {
      const textAmount = parsedCandidates[0];
      if (Math.abs(textAmount - explicitParams.amount) > 0.001) {
        ambiguities.push(`Conflicting amounts: structured parameter ($${explicitParams.amount}) does not match amount in prompt text ($${textAmount}).`);
      }
    }
    if (rawExpressionMatches.length > 1 || uniqueNumericCandidates.length > 1) {
      ambiguities.push('Prompt text contains multiple ambiguous currency amounts while structured parameter is present.');
    }
  }

  if (amount === undefined && parsedCandidates.length > 0) {
    amount = parsedCandidates[0];
  }

  // Check if multiple conflicting amounts exist in phrasing like "send 100 or make it 200"
  const alternativeAmountPattern = /\b(-?[0-9]+(?:\.[0-9]{2})?)\s*(?:or|instead\s+of|rather\s+than)\s*(-?[0-9]+(?:\.[0-9]{2})?)\b/i;
  if (alternativeAmountPattern.test(text)) {
    ambiguities.push('Conflicting alternative amounts specified in request.');
  }

  // 3. Extract Recipient from text and check for conflicts
  const foundRecipients: string[] = [];

  // Target recipient patterns:
  // e.g. "to account DEMO002", "to DEMO002.", "to alice.eth", "recipient: bob_miller"
  const targetPatterns = [
    /\b(?:to|recipient:?)\s+(?:account\s+|acc\s+)?([a-zA-Z0-9_.-]+)/gi,
  ];

  for (const pat of targetPatterns) {
    let match;
    while ((match = pat.exec(text)) !== null) {
      let candidate = match[1].trim();
      // Strip trailing sentence punctuation: . , ; : ! ? without damaging valid identifiers
      candidate = candidate.replace(/[.,;:!?]+$/, '').trim();

      const ignoredWords = ['the', 'my', 'account', 'acc', 'a', 'his', 'her', 'their', 'someone', 'anyone'];
      if (candidate && !ignoredWords.includes(candidate.toLowerCase())) {
        if (!foundRecipients.includes(candidate)) {
          foundRecipients.push(candidate);
        }
      }
    }
  }

  // Check for alternative recipients in phrasing like "to alice.eth or bob_miller"
  const alternativeRecipPattern = /\b(?:to|recipient:?)\s+(?:account\s+|acc\s+)?([a-zA-Z0-9_.-]+)\s+(?:or|and)\s+(?:to\s+)?(?:account\s+|acc\s+)?([a-zA-Z0-9_.-]+)\b/gi;
  let altMatch;
  while ((altMatch = alternativeRecipPattern.exec(text)) !== null) {
    for (const group of [altMatch[1], altMatch[2]]) {
      const c = group.replace(/[.,;:!?]+$/, '').trim();
      const ignoredWords = ['the', 'my', 'account', 'acc', 'a', 'his', 'her', 'their', 'someone', 'anyone'];
      if (c && !ignoredWords.includes(c.toLowerCase()) && !foundRecipients.includes(c)) {
        foundRecipients.push(c);
      }
    }
  }

  // Check allowlisted demo recipients, but ignore if preceded by "from (account)?"
  for (const demoRecip of DEMO_RECIPIENTS) {
    const fromPattern = new RegExp(`\\bfrom\\s+(?:account\\s+)?${demoRecip}\\b`, 'i');
    if (lower.includes(demoRecip.toLowerCase()) && !fromPattern.test(text)) {
      if (!foundRecipients.includes(demoRecip)) {
        foundRecipients.push(demoRecip);
      }
    }
  }

  if (foundRecipients.length > 1) {
    ambiguities.push(`Multiple distinct recipients detected in instruction: ${foundRecipients.join(' and ')}.`);
  }

  // Check for conflict between explicit parameter and prompt text
  if (explicitParams?.recipient && foundRecipients.length > 0) {
    const textRecip = foundRecipients[0];
    const expRecip = explicitParams.recipient.trim();
    if (textRecip.toLowerCase() !== expRecip.toLowerCase()) {
      ambiguities.push(`Conflicting recipients: structured parameter "${expRecip}" does not match recipient in prompt text "${textRecip}".`);
    }
    if (foundRecipients.length > 1) {
      ambiguities.push(`Prompt text contains multiple recipients (${foundRecipients.join(', ')}) while structured parameter specifies "${expRecip}".`);
    }
  }

  if (!recipient && foundRecipients.length > 0) {
    recipient = foundRecipients[0];
  }

  // 4. Extract Memo if phrased like "for dinner" or "memo: ..." or "with memo '...'"
  if (!memo) {
    const memoMatch = text.match(/\b(?:for|memo:?|note:?|with\s+memo)\s+["']?([^"'\n,.]+)["']?/i);
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

  // 6. Data Exfiltration Scan (Check prompt text, deobfuscated input, and memo)
  const textAndMemoToCheck = [deobfuscated, explicitParams?.memo].filter(Boolean).join(' ');
  for (const pattern of DATA_EXFILTRATION_PATTERNS) {
    if (pattern.test(textAndMemoToCheck)) {
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
    if (ambiguities.some(a => a.includes('Malformed') || a.includes('Negative'))) {
      threats.push('INVALID_TRANSACTION');
    }
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
