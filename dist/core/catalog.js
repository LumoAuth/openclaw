import { readPackageJson } from "../package-root.js";
export const RISKS = ['read', 'write', 'execute', 'external', 'destructive', 'admin'];
let cached;
/** The vendored contract (contract/catalog), loaded once. */
export function loadContract() {
    if (cached)
        return cached;
    cached = {
        host: readPackageJson('contract/catalog/openclaw.json'),
        mcpVerbs: readPackageJson('contract/catalog/mcp-verbs.json'),
        capabilities: readPackageJson('contract/catalog/capabilities.json'),
        presets: readPackageJson('contract/catalog/presets.json'),
    };
    return cached;
}
/** Look a tool up by its (alias-resolved) name: exact names first, then `prefix*` entries (longest first). */
export function findCatalogTool(catalog, name) {
    const exact = catalog.tools.find((t) => !t.name.endsWith('*') && t.name === name);
    if (exact)
        return exact;
    let best;
    for (const t of catalog.tools) {
        if (!t.name.endsWith('*'))
            continue;
        const prefix = t.name.slice(0, -1);
        if (name.startsWith(prefix) && (!best || prefix.length > best.name.length - 1))
            best = t;
    }
    return best;
}
