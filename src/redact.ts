/**
 * Central redaction layer. Every string that can leave the broker (tool
 * responses, error messages, audit detail, relayed header values) passes
 * through one SecretRedactor built from every secret the broker holds.
 *
 * The redactor covers the wire representations the broker itself creates:
 * the raw value, its NFC and NFD normalisations, standard and URL-safe
 * Base64 (Basic authorization) at every byte alignment, percent-encoding,
 * form-encoding (query-string credentials), and the JSON string-escaped
 * form an upstream produces when it quotes the secret in a JSON body. It
 * also covers hex, and the raw, hex and percent-encoded forms match in any
 * letter case. Base64 stays case-sensitive: changing its case changes the
 * bytes it decodes to.
 *
 * Truncated output is cut back by a fixed amount that depends only on the
 * secrets' lengths, never on the text, so the cut cannot be used as an
 * oracle for a secret prefix.
 *
 * Honest limit: an upstream that applies an arbitrary one-way transformation
 * to a secret (hashing, encryption, custom encoding) produces output no
 * redactor can recognise. The defence against that is scoped grants and
 * metadata-only responses, not string matching. The same goes for an
 * upstream that echoes only part of a secret: fragments are not matched,
 * because a fragment of a credential such as "user:password" is an ordinary
 * word that would be cut out of every response.
 */

const REPLACEMENT = "[REDACTED]";
const MIN_VARIANT_LENGTH = 4;

/**
 * Base64 of the secret as it appears when it starts at byte offset 1 or 2
 * of a larger encoded value (for example inside base64 of a JSON wrapper).
 * The leading characters that mix with the unknown preceding bytes, and the
 * trailing partial group that mixes with the following bytes, are dropped.
 */
function shiftedBase64(bytes: Buffer, offset: 1 | 2, urlSafe: boolean): string {
  const padded = Buffer.concat([Buffer.alloc(offset), bytes]);
  const encoded = padded.toString(urlSafe ? "base64url" : "base64");
  const start = offset === 1 ? 2 : 3;
  const end = Math.floor(padded.length / 3) * 4;
  return end > start ? encoded.slice(start, end) : "";
}

/** Every wire form of a secret, mapped to whether it matches in any letter case. */
function wireVariants(secret: string): Map<string, boolean> {
  const bases = new Set([secret, secret.normalize("NFC"), secret.normalize("NFD")]);
  const variants = new Set<string>();
  const anyCase = new Set<string>();
  for (const base of bases) {
    if (base.length === 0) continue;
    const bytes = Buffer.from(base, "utf8");
    anyCase.add(base);
    anyCase.add(bytes.toString("hex"));
    anyCase.add(encodeURIComponent(base));
    variants.add(bytes.toString("base64"));
    variants.add(bytes.toString("base64url"));
    for (const offset of [1, 2] as const) {
      variants.add(shiftedBase64(bytes, offset, false));
      variants.add(shiftedBase64(bytes, offset, true));
    }
    // Form encoding as URLSearchParams serialises it (space becomes "+").
    variants.add(new URLSearchParams([["v", base]]).toString().slice(2));
    // JSON string escaping, with and without the escaped slash some encoders emit.
    const json = JSON.stringify(base).slice(1, -1);
    variants.add(json);
    variants.add(json.replace(/\//gu, "\\/"));
  }
  const out = new Map<string, boolean>();
  for (const variant of variants) out.set(variant, false);
  for (const variant of anyCase) out.set(variant, true);
  return out;
}

function matcher(variant: string, anyCase: boolean): RegExp {
  const escaped = variant.replace(/[\\^$.*+?()[\]{}|/]/gu, "\\$&");
  return new RegExp(escaped, anyCase ? "giu" : "gu");
}

export class SecretRedactor {
  private readonly matchers: RegExp[];
  /** Length of the longest variant; a truncated text loses one less than this. */
  private readonly longest: number;

  public constructor(secrets: Iterable<string>) {
    const all = new Map<string, boolean>();
    for (const secret of secrets) {
      if (!secret) continue;
      for (const [variant, anyCase] of wireVariants(secret)) {
        if (variant.length >= MIN_VARIANT_LENGTH) all.set(variant, anyCase || all.get(variant) === true);
      }
    }
    // Longest first so a long variant is not mangled by a shorter one.
    const ordered = [...all].sort(([a], [b]) => b.length - a.length);
    this.matchers = ordered.map(([variant, anyCase]) => matcher(variant, anyCase));
    this.longest = ordered[0]?.[0].length ?? 0;
  }

  /** Replace every known secret representation in the text. */
  public redact(text: string): string {
    let out = text;
    for (const match of this.matchers) out = out.replace(match, REPLACEMENT);
    return out;
  }

  /**
   * Redact text that was cut at a byte budget. The tail could hold a prefix
   * of a secret, so the longest possible such prefix is always removed. The
   * amount removed depends only on the secrets' lengths, not on what the
   * text ends with, so the cut gives nothing away.
   */
  public redactTruncated(text: string): string {
    const out = this.redact(text);
    const strip = Math.min(out.length, Math.max(0, this.longest - 1));
    if (strip === 0) return out;
    return `${out.slice(0, out.length - strip)}${REPLACEMENT}`;
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
