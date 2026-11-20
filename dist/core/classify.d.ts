import { type CatalogTool, type HostCatalog, type McpVerbs, type Risk } from './catalog.ts';
import { type GuardEnv } from './paths.ts';
/** SPEC §4: what a tool call is, for the rules. */
export interface Classification {
    /** Host tool name after the catalog's aliases. */
    tool: string;
    capability: string;
    risk: Risk;
    ingestsUntrusted: boolean;
    persistsInstructions: boolean;
    egress: boolean;
    /** Absolute paths (lexical form) from pathArgs, patchArgs and derivedPaths. */
    paths: string[];
    /** First non-empty commandArgs value. */
    command: string | null;
    /** MCP server (sanitised) and the tool's own name, for MCP tools. */
    server: string | null;
    mcpTool: string | null;
    /** The catalog's tool rule (§5.2). */
    hardRule: 'deny' | 'approve' | null;
    /** The wrapper's name when the call came through a dispatcher tool (§4.1a). */
    dispatchedBy: string | null;
}
export interface ClassifyInput {
    toolName: string;
    params: Record<string, unknown>;
    derivedPaths?: readonly string[] | undefined;
}
export interface ClassifyResult {
    classification: Classification;
    /** The catalog entry, when the tool is a known built-in. */
    entry: CatalogTool | undefined;
    /** Every commandArgs value (shell text / code) to scan. */
    commands: string[];
    /** Working directory for shell tokens: the tool's workdir/cwd argument, else the host's. */
    workdir: string;
    /** For a dispatched call: the tool name as the model gave it and the arguments that the tool gets. */
    dispatched?: {
        rawName: string;
        args: Record<string, unknown>;
    } | undefined;
}
/**
 * Paths named by a patch: `*** Add File:`, `*** Update File:`, `*** Delete
 * File:`, `*** Move to:` lines, and unified-diff `---`/`+++` headers (after
 * the `a/`/`b/` prefix; `/dev/null` ignored). In order, without duplicates.
 */
export declare function patchPaths(patch: string): string[];
/**
 * §4.4: for MCP tools and tools not in the catalog, every string value at any
 * depth that starts with `/` or `~/` (or is exactly `~`) is a path.
 */
export declare function pathLikeArgumentValues(params: unknown): string[];
/** Split `<server>__<tool>` (after the host's MCP prefix). */
export declare function splitMcpName(catalog: HostCatalog, name: string): {
    server: string;
    tool: string;
} | null;
/**
 * OpenClaw's tool-search ids are `<source>:<plugin>:<tool name>`
 * (`openclaw:core:web_fetch`, `mcp:github:github__list_issues`); the tool
 * runs, and reaches the hook, under its plain name.
 */
export declare function catalogIdToName(idOrName: string): string;
/**
 * SPEC §4: classify a call. A dispatcher wrapper (§4.1a) is classified as
 * the call that it dispatches; without a resolvable tool name it stays
 * `tool:<wrapper>` (risk execute).
 */
export declare function classify(catalog: HostCatalog, verbs: McpVerbs, env: GuardEnv, input: ClassifyInput): ClassifyResult;
