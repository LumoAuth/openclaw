import { readPackageJson } from '../package-root.ts';

export type Risk = 'read' | 'write' | 'execute' | 'external' | 'destructive' | 'admin';
export const RISKS: readonly Risk[] = ['read', 'write', 'execute', 'external', 'destructive', 'admin'];

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
  dispatcher?: { nameArgs: string[]; argsArg: string };
}

export interface HostCatalog {
  host: string;
  verifiedAgainst?: string;
  aliases: Record<string, string>;
  mcp: { separator: string; prefix: string };
  tools: CatalogTool[];
}

export interface McpVerbs {
  order: Risk[];
  verbs: Partial<Record<Risk, string[]>>;
  untrustedServerWords: string[];
  untrustedToolWords: string[];
}

export interface CapabilityCatalog {
  capabilities: Record<string, { label: string; risk: Risk }>;
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

let cached: Contract | undefined;

/** The vendored contract (contract/catalog), loaded once. */
export function loadContract(): Contract {
  if (cached) return cached;
  cached = {
    host: readPackageJson<HostCatalog>('contract/catalog/openclaw.json'),
    mcpVerbs: readPackageJson<McpVerbs>('contract/catalog/mcp-verbs.json'),
    capabilities: readPackageJson<CapabilityCatalog>('contract/catalog/capabilities.json'),
    presets: readPackageJson<Presets>('contract/catalog/presets.json'),
  };
  return cached;
}

/** Look a tool up by its (alias-resolved) name: exact names first, then `prefix*` entries (longest first). */
export function findCatalogTool(catalog: HostCatalog, name: string): CatalogTool | undefined {
  const exact = catalog.tools.find((t) => !t.name.endsWith('*') && t.name === name);
  if (exact) return exact;
  let best: CatalogTool | undefined;
  for (const t of catalog.tools) {
    if (!t.name.endsWith('*')) continue;
    const prefix = t.name.slice(0, -1);
    if (name.startsWith(prefix) && (!best || prefix.length > best.name.length - 1)) best = t;
  }
  return best;
}
