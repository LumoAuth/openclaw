/**
 * Agent capability matching, exactly as the LumoAuth server does it
 * (contract/vectors/agent-capabilities.json): the canonical form is
 * `<resource>:<action>`; a capability covers an action when it is `*`, equal
 * to it, or a `prefix:*` wildcard of it.
 */
export declare function normalizeCapability(input: string): string;
export declare function covers(capability: string, action: string): boolean;
export declare function anyCovers(capabilities: readonly string[], action: string): boolean;
/** `<server>` / `<tool>` parts of a capability: lower-case, `[a-z0-9_-]` only. */
export declare function sanitizeName(name: string): string;
