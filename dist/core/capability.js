/**
 * Agent capability matching, exactly as the LumoAuth server does it
 * (contract/vectors/agent-capabilities.json): the canonical form is
 * `<resource>:<action>`; a capability covers an action when it is `*`, equal
 * to it, or a `prefix:*` wildcard of it.
 */
const TRIM_CHARS = new Set([' ', '\t', '\n', '\r', '\0', '\x0B']);
export function normalizeCapability(input) {
    let start = 0;
    let end = input.length;
    while (start < end && TRIM_CHARS.has(input[start]))
        start++;
    while (end > start && TRIM_CHARS.has(input[end - 1]))
        end--;
    // ASCII-only lower-casing, as PHP's strtolower.
    let s = input.slice(start, end).replace(/[A-Z]/g, (c) => c.toLowerCase());
    s = s.replace(/\./g, ':').replace(/:{2,}/g, ':');
    s = s.replace(/^:+/, '').replace(/:+$/, '');
    return s;
}
export function covers(capability, action) {
    const cap = normalizeCapability(capability);
    const act = normalizeCapability(action);
    if (cap === '' || act === '')
        return false;
    if (cap === '*' || cap === act)
        return true;
    if (cap.endsWith(':*'))
        return act.startsWith(cap.slice(0, -1));
    return false;
}
export function anyCovers(capabilities, action) {
    for (const cap of capabilities) {
        if (typeof cap === 'string' && covers(cap, action))
            return true;
    }
    return false;
}
/** `<server>` / `<tool>` parts of a capability: lower-case, `[a-z0-9_-]` only. */
export function sanitizeName(name) {
    return name.toLowerCase().replace(/[^a-z0-9_-]/g, '_');
}
