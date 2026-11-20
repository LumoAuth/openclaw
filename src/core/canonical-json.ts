import { createHash } from 'node:crypto';

/**
 * Canonical JSON (SPEC §7.4): object keys sorted at every level, no
 * whitespace, JSON.stringify-compatible numbers and strings. `undefined`,
 * functions and symbols are dropped from objects (null in arrays), as
 * JSON.stringify does; objects with toJSON() are serialised through it.
 */
export function canonicalJson(value: unknown): string {
  const seen = new Set<object>();
  const walk = (v: unknown, inArray: boolean): string | undefined => {
    if (v !== null && typeof v === 'object' && typeof (v as { toJSON?: unknown }).toJSON === 'function') {
      v = (v as { toJSON: () => unknown }).toJSON();
    }
    if (v === null) return 'null';
    switch (typeof v) {
      case 'string':
      case 'number':
      case 'boolean':
        return JSON.stringify(v);
      case 'bigint':
        return JSON.stringify(v.toString());
      case 'undefined':
      case 'function':
      case 'symbol':
        return inArray ? 'null' : undefined;
    }
    const obj = v as object;
    if (seen.has(obj)) throw new TypeError('canonicalJson: circular structure');
    seen.add(obj);
    let out: string;
    if (Array.isArray(obj)) {
      out = `[${obj.map((x) => walk(x, true) ?? 'null').join(',')}]`;
    } else {
      const rec = obj as Record<string, unknown>;
      const parts: string[] = [];
      for (const k of Object.keys(rec).sort()) {
        const s = walk(rec[k], false);
        if (s !== undefined) parts.push(`${JSON.stringify(k)}:${s}`);
      }
      out = `{${parts.join(',')}}`;
    }
    seen.delete(obj);
    return out;
  };
  return walk(value, false) ?? 'null';
}

/** Hex SHA-256 of the canonical JSON of the arguments. */
export function argumentsSha256(args: unknown): string {
  let text: string;
  try {
    text = canonicalJson(args ?? {});
  } catch {
    text = '"[unserializable]"';
  }
  return createHash('sha256').update(text, 'utf8').digest('hex');
}
