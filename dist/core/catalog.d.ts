export type Risk = 'read' | 'write' | 'execute' | 'external' | 'destructive' | 'admin';
export declare const RISKS: readonly Risk[];
export interface CatalogTool {
    name: string;
    capability: string;
    risk: Risk;
    pathArgs?: string[];
    commandArgs?: string[];
    patchArgs?: string[];
    ingestsUntrusted?: boolean;
    egress?: boolean;
    persistsInstructions?: boolean;
    hardRule?: 'deny' | 'approve';
    hardRuleActions?: {
        argument: string;
        approve?: string[];
        deny?: string[];
        allowWithoutHardRule?: string[];
        approveOtherwise?: boolean;
    };
    /** A wrapper that runs another tool (SPEC §4.1a): the argument names holding its name and its arguments. */
    dispatcher?: {
        nameArgs: string[];
        argsArg: string;
    };
}
export interface HostCatalog {
    host: string;
    verifiedAgainst?: string;
    aliases: Record<string, string>;
    mcp: {
        separator: string;
        prefix: string;
    };
    tools: CatalogTool[];
}
export interface McpVerbs {
    order: Risk[];
    verbs: Partial<Record<Risk, string[]>>;
    untrustedServerWords: string[];
    untrustedToolWords: string[];
}
export interface CapabilityCatalog {
    capabilities: Record<string, {
        label: string;
        risk: Risk;
    }>;
    mcpRiskLabels: Partial<Record<Risk, string>>;
}
export interface Preset {
    label: string;
    capabilities: string[];
    mcp: Risk[];
}
export interface Presets {
    default: string;
    presets: Record<string, Preset>;
}
export interface Contract {
    host: HostCatalog;
    mcpVerbs: McpVerbs;
    capabilities: CapabilityCatalog;
    presets: Presets;
}
/** The vendored contract (contract/catalog), loaded once. */
export declare function loadContract(): Contract;
/** Look a tool up by its (alias-resolved) name: exact names first, then `prefix*` entries (longest first). */
export declare function findCatalogTool(catalog: HostCatalog, name: string): CatalogTool | undefined;
