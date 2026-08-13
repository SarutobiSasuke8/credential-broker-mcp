/**
 * Central redaction layer. Every string that can leave the broker (tool
 * responses, error messages, audit detail, relayed header values) passes
 * through one SecretRedactor built from every secret the broker holds.
 *
 * The redactor covers the wire representations the broker itself creates:
 * the raw value, its NFC and NFD normalisations, standard and URL-safe
 * Base64 (Basic authorization), percent-encoding, and form-encoding
 * (query-string credentials). It also strips a trailing partial secret from
 * truncated output so a byte cap cannot expose a secret prefix.
 *
 * Honest limit: an upstream that applies an arbitrary one-way transformation
 * to a secret (hashing, encryption, custom encoding) produces output no
 * redactor can recognise. The defence against that is scoped grants and
 * metadata-only responses, not string matching.
 */

const REPLACEMENT = "[REDACTED]";
const MIN_VARIANT_LENGTH = 4;
const MIN_PARTIAL_LENGTH = 4;

function wireVariants(secret: string): string[] {
  const bases = new Set([secret, secret.normalize("NFC"), secret.normalize("NFD")]);
  const variants = new Set<string>();
  for (const base of bases) {
    if (base.length === 0) continue;
    variants.add(base);
    variants.add(Buffer.from(base, "utf8").toString("base64"));
    variants.add(Buffer.from(base, "utf8").toString("base64url"));
    variants.add(encodeURIComponent(base));
    // Form encoding as URLSearchParams serialises it (space becomes "+").
    variants.add(new URLSearchParams([["v", base]]).toString().slice(2));
  }
  return [...variants];
}

export class SecretRedactor {
  private readonly variants: string[];

  public constructor(secrets: Iterable<string>) {
    const all = new Set<string>();
    for (const secret of secrets) {
      if (!secret) continue;
      for (const variant of wireVariants(secret)) {
        if (variant.length >= MIN_VARIANT_LENGTH) all.add(variant);
      }
    }
    // Longest first so a long variant is not mangled by a shorter one.
    this.variants = [...all].sort((a, b) => b.length - a.length);
  }

  /** Replace every known secret representation in the text. */
  public redact(text: string): string {
    let out = text;
    for (const variant of this.variants) {
      if (out.includes(variant)) out = out.split(variant).join(REPLACEMENT);
    }
    return out;
  }

  /**
   * Redact text that was cut at a byte budget: additionally removes the
   * longest trailing run that is a prefix of any secret representation, so
   * truncation cannot leave a partial secret behind.
   */
  public redactTruncated(text: string): string {
    const out = this.redact(text);
    let bestStrip = 0;
    for (const variant of this.variants) {
      const maxLen = Math.min(variant.length - 1, out.length);
      for (let len = maxLen; len >= MIN_PARTIAL_LENGTH; len -= 1) {
        if (len <= bestStrip) break;
        if (out.endsWith(variant.slice(0, len))) {
          bestStrip = len;
          break;
        }
      }
    }
    if (bestStrip === 0) return out;
    return `${out.slice(0, out.length - bestStrip)}${REPLACEMENT}`;
  }

  /** Redact an Error's message chain (message plus nested causes). */
  public redactError(error: unknown): string {
    const parts: string[] = [];
    let current: unknown = error;
    let depth = 0;
    while (current && depth < 5) {
      if (current instanceof Error) {
        parts.push(`${current.name}: ${current.message}`);
        current = current.cause;
      } else {
        parts.push(String(current));
        break;
      }
      depth += 1;
    }
    return this.redact(parts.join(" <- ")).slice(0, 500);
  }
}

/** A redactor that changes nothing; for construction before secrets load. */
export const NULL_REDACTOR = new SecretRedactor([]);
