/**
 * BANKISM Input Normalizer
 * Performs Unicode NFKC normalization, strips invisible/zero-width characters,
 * maps homoglyphs, detects token-splitting obfuscation, and returns a sanitized
 * canonical text stream for heuristic threat analysis.
 */

export interface NormalizationResult {
  original: string;
  normalised: string;
  deobfuscated_for_analysis: string;
  obfuscation_detected: boolean;
  obfuscation_details: string[];
}

// Map of common homoglyphs (Cyrillic, Greek, Latin lookalikes) used in evasion attacks
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic lowercase to Latin
  '\u0430': 'a', // а
  '\u0435': 'e', // е
  '\u043E': 'o', // о
  '\u0440': 'p', // р
  '\u0441': 'c', // с
  '\u0443': 'y', // у
  '\u0445': 'x', // х
  '\u0456': 'i', // і
  '\u0458': 'j', // ј
  '\u0455': 's', // ѕ
  '\u0432': 'b', // в
  '\u043D': 'h', // н
  '\u0442': 't', // т
  '\u043C': 'm', // м
  // Cyrillic uppercase to Latin
  '\u0410': 'A', // А
  '\u0412': 'B', // В
  '\u0415': 'E', // Е
  '\u041A': 'K', // К
  '\u041C': 'M', // М
  '\u041D': 'H', // Н
  '\u041E': 'O', // О
  '\u0420': 'P', // Р
  '\u0421': 'C', // С
  '\u0422': 'T', // Т
  '\u0425': 'X', // Х
  // Greek lookalikes
  '\u0391': 'A', // Α
  '\u0392': 'B', // Β
  '\u0395': 'E', // Ε
  '\u0396': 'Z', // Ζ
  '\u0397': 'H', // Η
  '\u0399': 'I', // Ι
  '\u039A': 'K', // Κ
  '\u039C': 'M', // Μ
  '\u039D': 'N', // Ν
  '\u039F': 'O', // Ο
  '\u03A1': 'P', // Ρ
  '\u03A4': 'T', // Τ
  '\u03A5': 'Y', // Y
  '\u03A7': 'X', // Χ
  '\u03BF': 'o', // ο
  '\u03C1': 'p', // ρ
};

// Zero-width and hidden formatting unicode code points
const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u200E\u200F\u202A-\u202E\uFFF9-\uFFFB]/g;

export function normaliseInput(input: string): NormalizationResult {
  const original = String(input ?? '');
  const obfuscationDetails: string[] = [];
  let obfuscationDetected = false;

  // 1. Check for zero-width / invisible characters
  const zeroWidthMatches = original.match(ZERO_WIDTH_REGEX);
  if (zeroWidthMatches && zeroWidthMatches.length > 0) {
    obfuscationDetected = true;
    obfuscationDetails.push(`Found ${zeroWidthMatches.length} zero-width / invisible unicode characters.`);
  }

  // 2. Remove zero-width characters and control codes (except standard \n, \t)
  const strippedInvisible = original
    .replace(ZERO_WIDTH_REGEX, '')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

  // 3. Unicode NFKC normalization (Normal Form Compatibility Composition)
  const nfkcNormalized = strippedInvisible.normalize('NFKC');

  // 4. Check & replace homoglyphs
  let homoglyphCount = 0;
  let homoglyphReplaced = '';
  for (const char of nfkcNormalized) {
    if (HOMOGLYPH_MAP[char]) {
      homoglyphReplaced += HOMOGLYPH_MAP[char];
      homoglyphCount++;
    } else {
      homoglyphReplaced += char;
    }
  }

  if (homoglyphCount > 0) {
    obfuscationDetected = true;
    obfuscationDetails.push(`Detected and mapped ${homoglyphCount} homoglyph character substitutions.`);
  }

  // 5. Detect suspicious token-splitting (e.g., "i g n o r e" or "d r o p   t a b l e")
  const tokenSplitRegex = /(?:\b[a-zA-Z]\s+){4,}[a-zA-Z]\b/g;
  const tokenSplitMatches = homoglyphReplaced.match(tokenSplitRegex);
  if (tokenSplitMatches && tokenSplitMatches.length > 0) {
    obfuscationDetected = true;
    obfuscationDetails.push(`Detected token-splitting spacing pattern across letters: "${tokenSplitMatches[0].trim()}".`);
  }

  // 6. Build deobfuscated string for threat scanner analysis
  // Collapses token-split single letters: "i g n o r e" -> "ignore"
  const collapsedTokenSplits = homoglyphReplaced.replace(tokenSplitRegex, (match) => {
    return match.replace(/\s+/g, '');
  });

  // Normalize excessive whitespace to single space
  const cleanSpacing = collapsedTokenSplits.replace(/\s+/g, ' ').trim();

  return {
    original,
    normalised: nfkcNormalized.trim(),
    deobfuscated_for_analysis: cleanSpacing.toLowerCase(),
    obfuscation_detected: obfuscationDetected,
    obfuscation_details: obfuscationDetails,
  };
}
