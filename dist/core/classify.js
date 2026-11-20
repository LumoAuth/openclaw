import { sanitizeName } from "./capability.js";
import { findCatalogTool } from "./catalog.js";
import { mcpRisk } from "./mcp-risk.js";
import { resolvePath } from "./paths.js";
/** Names of arguments holding a working directory for shell and code tools. */
const WORKDIR_ARGS = ['workdir', 'cwd'];
/**
 * Paths named by a patch: `*** Add File:`, `*** Update File:`, `*** Delete
 * File:`, `*** Move to:` lines, and unified-diff `---`/`+++` headers (after
 * the `a/`/`b/` prefix; `/dev/null` ignored). In order, without duplicates.
 */
export function patchPaths(patch) {
    const out = [];
    const add = (p) => {
        const t = p.trim();
        if (t && t !== '/dev/null' && !out.includes(t))
            out.push(t);
    };
    for (const raw of patch.split(/\r?\n/)) {
        const m = /^\*\*\* (?:Add File|Update File|Delete File|Move to): (.*)$/.exec(raw);
        if (m) {
            add(m[1]);
            continue;
        }
        const d = /^(?:---|\+\+\+) (.+)$/.exec(raw);
        if (d) {
            let p = d[1].split('\t')[0].trim();
            if (p === '/dev/null')
                continue;
            if (p.startsWith('a/') || p.startsWith('b/'))
                p = p.slice(2);
            add(p);
        }
    }
    return out;
}
/** At most this many string values are looked at for path-like arguments (§4.4). */
const MAX_ARGUMENT_STRINGS = 200;
/**
 * §4.4: for MCP tools and tools not in the catalog, every string value at any
 * depth that starts with `/` or `~/` (or is exactly `~`) is a path.
 */
export function pathLikeArgumentValues(params) {
    const out = [];
    let seen = 0;
    const walk = (v, depth) => {
        if (seen >= MAX_ARGUMENT_STRINGS || depth > 32)
            return;
        if (typeof v === 'string') {
            seen++;
            if (v === '~' || v.startsWith('/') || v.startsWith('~/'))
                out.push(v);
            return;
        }
        if (Array.isArray(v)) {
            for (const x of v)
                walk(x, depth + 1);
        }
        else if (v && typeof v === 'object') {
            for (const x of Object.values(v))
                walk(x, depth + 1);
        }
    };
    walk(params, 0);
    return out;
}
function stringValues(v) {
    if (typeof v === 'string')
        return v.trim() === '' ? [] : [v];
    if (Array.isArray(v))
        return v.filter((x) => typeof x === 'string' && x.trim() !== '');
    return [];
}
/** Split `<server>__<tool>` (after the host's MCP prefix). */
export function splitMcpName(catalog, name) {
    const { separator, prefix } = catalog.mcp;
    if (prefix && !name.startsWith(prefix))
        return null;
    const rest = name.slice(prefix.length);
    const idx = rest.indexOf(separator);
    if (idx <= 0 || idx + separator.length >= rest.length)
        return null;
    return { server: rest.slice(0, idx), tool: rest.slice(idx + separator.length) };
}
function toolHardRule(entry, params) {
    if (!entry)
        return null;
    if (entry.hardRule)
        return entry.hardRule;
    const rule = entry.hardRuleActions;
    if (!rule)
        return null;
    const raw = params[rule.argument];
    const action = typeof raw === 'string' ? raw.trim() : '';
    if (rule.deny?.includes(action))
        return 'deny';
    if (rule.approve?.includes(action))
        return 'approve';
    if (rule.approveOtherwise && !(rule.allowWithoutHardRule ?? []).includes(action))
        return 'approve';
    return null;
}
/**
 * OpenClaw's tool-search ids are `<source>:<plugin>:<tool name>`
 * (`openclaw:core:web_fetch`, `mcp:github:github__list_issues`); the tool
 * runs, and reaches the hook, under its plain name.
 */
export function catalogIdToName(idOrName) {
    const m = /^[A-Za-z0-9_-]+:[^:\s]*:(.+)$/.exec(idOrName);
    return m ? m[1] : idOrName;
}
/**
 * SPEC §4: classify a call. A dispatcher wrapper (§4.1a) is classified as
 * the call that it dispatches; without a resolvable tool name it stays
 * `tool:<wrapper>` (risk execute).
 */
export function classify(catalog, verbs, env, input) {
    const params = input.params ?? {};
    const wrapperName = catalog.aliases[input.toolName] ?? input.toolName;
    const wrapper = findCatalogTool(catalog, wrapperName);
    if (wrapper?.dispatcher) {
        let rawName;
        for (const n of wrapper.dispatcher.nameArgs) {
            const v = params[n];
            if (typeof v === 'string' && v.trim() !== '') {
                rawName = catalogIdToName(v.trim());
                break;
            }
        }
        const innerArgsRaw = params[wrapper.dispatcher.argsArg];
        const innerArgs = innerArgsRaw && typeof innerArgsRaw === 'object' && !Array.isArray(innerArgsRaw) ? innerArgsRaw : {};
        const innerEntry = rawName ? findCatalogTool(catalog, catalog.aliases[rawName] ?? rawName) : undefined;
        // A dispatcher that names another dispatcher is not resolved (it asks).
        if (rawName && !innerEntry?.dispatcher) {
            const inner = classifyDirect(catalog, verbs, env, { toolName: rawName, params: innerArgs, derivedPaths: input.derivedPaths });
            inner.classification.dispatchedBy = wrapperName;
            inner.dispatched = { rawName, args: innerArgs };
            return inner;
        }
        return classifyDirect(catalog, verbs, env, { ...input, params: {} });
    }
    return classifyDirect(catalog, verbs, env, input);
}
function classifyDirect(catalog, verbs, env, input) {
    const params = input.params ?? {};
    const tool = catalog.aliases[input.toolName] ?? input.toolName;
    const entry = findCatalogTool(catalog, tool);
    let capability;
    let risk;
    let ingestsUntrusted = false;
    let server = null;
    let mcpTool = null;
    const mcp = entry ? null : splitMcpName(catalog, input.toolName);
    if (entry) {
        capability = entry.capability;
        risk = entry.risk;
        ingestsUntrusted = entry.ingestsUntrusted === true;
    }
    else if (mcp) {
        server = sanitizeName(mcp.server);
        mcpTool = mcp.tool;
        const r = mcpRisk(verbs, mcp.server, mcp.tool);
        risk = r.risk;
        ingestsUntrusted = r.ingestsUntrusted;
        capability = `mcp:${server}:${risk}:${sanitizeName(mcp.tool)}`;
    }
    else {
        capability = `tool:${sanitizeName(tool)}`;
        risk = 'execute';
    }
    const commands = [];
    for (const name of entry?.commandArgs ?? [])
        commands.push(...stringValues(params[name]));
    const hostCwd = env.cwd;
    let workdir = hostCwd;
    if (entry?.commandArgs?.length) {
        for (const name of WORKDIR_ARGS) {
            const v = params[name];
            if (typeof v === 'string' && v.trim() !== '') {
                workdir = resolvePath(v, hostCwd, env);
                break;
            }
        }
    }
    const rawPaths = [];
    for (const name of entry?.pathArgs ?? [])
        rawPaths.push(...stringValues(params[name]));
    for (const name of entry?.patchArgs ?? []) {
        for (const v of stringValues(params[name]))
            rawPaths.push(...patchPaths(v));
    }
    for (const p of input.derivedPaths ?? [])
        if (typeof p === 'string' && p.trim() !== '')
            rawPaths.push(p);
    if (!entry)
        rawPaths.push(...pathLikeArgumentValues(params));
    const paths = [];
    for (const p of rawPaths) {
        const abs = resolvePath(p, env.workspace, env);
        if (!paths.includes(abs))
            paths.push(abs);
    }
    return {
        classification: {
            tool,
            capability,
            risk,
            ingestsUntrusted,
            persistsInstructions: entry?.persistsInstructions === true,
            egress: entry?.egress === true,
            paths,
            command: commands[0] ?? null,
            server,
            mcpTool,
            hardRule: toolHardRule(entry, params),
            dispatchedBy: null,
        },
        entry,
        commands,
        workdir,
    };
}
