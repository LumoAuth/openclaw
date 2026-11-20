/**
 * Canonical JSON (SPEC §7.4): object keys sorted at every level, no
 * whitespace, JSON.stringify-compatible numbers and strings. `undefined`,
 * functions and symbols are dropped from objects (null in arrays), as
 * JSON.stringify does; objects with toJSON() are serialised through it.
 */
export declare function canonicalJson(value: unknown): string;
/** Hex SHA-256 of the canonical JSON of the arguments. */
export declare function argumentsSha256(args: unknown): string;
