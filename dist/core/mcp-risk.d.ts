import type { McpVerbs, Risk } from './catalog.ts';
/**
 * Split a name into lower-case words at `_`, `-`, `.`, whitespace and
 * camelCase boundaries: `listIssues` → list, issues; `HTTPGet` → http, get.
 */
export declare function splitWords(name: string): string[];
export interface McpRisk {
    risk: Risk;
    ingestsUntrusted: boolean;
}
/** SPEC §4.3: risk and ingestsUntrusted of an MCP tool from its server and tool names. */
export declare function mcpRisk(verbs: McpVerbs, server: string, tool: string): McpRisk;
