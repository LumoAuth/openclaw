/**
 * Split a name into lower-case words at `_`, `-`, `.`, whitespace and
 * camelCase boundaries: `listIssues` → list, issues; `HTTPGet` → http, get.
 */
export function splitWords(name) {
    const words = [];
    for (const part of name.split(/[_\-.\s]+/)) {
        if (!part)
            continue;
        const pieces = part.match(/[A-Z0-9]+(?![a-z])|[A-Z]?[a-z0-9]+/g);
        if (!pieces)
            continue;
        for (const p of pieces)
            words.push(p.toLowerCase());
    }
    return words;
}
/** SPEC §4.3: risk and ingestsUntrusted of an MCP tool from its server and tool names. */
export function mcpRisk(verbs, server, tool) {
    const words = splitWords(tool);
    const lists = new Map();
    for (const r of verbs.order)
        lists.set(r, new Set(verbs.verbs[r] ?? []));
    let risk = 'execute';
    outer: for (const w of words) {
        for (const r of verbs.order) {
            if (lists.get(r)?.has(w)) {
                risk = r;
                break outer;
            }
        }
    }
    const admin = lists.get('admin') ?? new Set();
    if ((risk === 'read' || risk === 'write') && words.some((w) => admin.has(w)))
        risk = 'admin';
    let ingestsUntrusted = false;
    if (risk === 'read') {
        const serverWords = new Set(verbs.untrustedServerWords);
        const toolWords = new Set(verbs.untrustedToolWords);
        ingestsUntrusted = splitWords(server).some((w) => serverWords.has(w)) || words.some((w) => toolWords.has(w));
    }
    return { risk, ingestsUntrusted };
}
