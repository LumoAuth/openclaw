import type { Risk } from './catalog.ts';

export type Impact = 'low' | 'medium' | 'high' | 'critical';
export type Severity = 'info' | 'warning' | 'critical';

export const TITLE_MAX = 80;
export const DESCRIPTION_MAX = 480;
const VALUE_MAX = 80;
const COMMAND_MAX = 240;
const MAX_ARG_LINES = 5;
const HIDDEN_NAME = /password|secret|token|key|auth|cookie|credential/i;

export interface ApprovalText {
  title: string;
  description: string;
  impact: Impact;
  severity: Severity;
}

export function impactFor(risk: Risk): Impact {
  switch (risk) {
    case 'read':
      return 'low';
    case 'write':
      return 'medium';
    case 'execute':
    case 'external':
      return 'high';
    default:
      return 'critical';
  }
}

export function severityFor(risk: Risk, hardRule: boolean): Severity {
  if (hardRule) return 'critical';
  if (risk === 'read' || risk === 'write') return 'info';
  if (risk === 'execute' || risk === 'external') return 'warning';
  return 'critical';
}

/** Cut to `max` code points: the first max-1 and '…'. */
export function cut(text: string, max: number): string {
  const cps = Array.from(text);
  if (cps.length <= max) return text;
  return `${cps.slice(0, max - 1).join('')}…`;
}

/**
 * Make model-chosen text safe to show a person: newlines become '⏎', and
 * other control characters, bidirectional overrides and zero-width
 * characters become U+FFFD (they could hide or reorder what is shown).
 */
export function displayText(text: string): string {
  return text.replace(/\r\n|\r|\n/g, '⏎').replace(UNSAFE_CHARS, '�').replace(/\t/g, ' ');
}

// Built from a string: a regex literal holding U+2028 does not survive every
// TypeScript-to-JavaScript step (Node's type stripping turns it into a line break).
const UNSAFE_CHARS = new RegExp(
  '[\\u0000-\\u0008\\u000B-\\u001F\\u007F-\\u009F\\u061C\\u200B-\\u200F\\u2028-\\u202E\\u2060-\\u2069\\uFEFF]',
  'g',
);

function compareCodePoints(a: string, b: string): number {
  const ai = a[Symbol.iterator]();
  const bi = b[Symbol.iterator]();
  for (;;) {
    const x = ai.next();
    const y = bi.next();
    if (x.done) return y.done ? 0 : -1;
    if (y.done) return 1;
    const d = x.value.codePointAt(0)! - y.value.codePointAt(0)!;
    if (d !== 0) return d;
  }
}

function valueText(v: unknown): string {
  if (typeof v === 'string') return v;
  try {
    const s = JSON.stringify(v);
    return s === undefined ? String(v) : s;
  } catch {
    return '[unprintable]';
  }
}

export interface ApprovalTextInput {
  classification: { tool: string; capability: string; risk: Risk; server?: string | null; mcpTool?: string | null };
  args: Record<string, unknown>;
  /** Names of the tool's command arguments (catalog commandArgs). */
  commandArgs?: readonly string[] | undefined;
  why: string;
  hardRule?: boolean;
}

/** SPEC §6.4: title and description, built only from the classification and the arguments. */
export function approvalText(input: ApprovalTextInput): ApprovalText {
  const c = input.classification;
  const title =
    c.server && c.mcpTool ? `Allow ${displayText(c.mcpTool)} on ${displayText(c.server)}?` : `Allow ${displayText(c.tool)}?`;

  const lines = [`Why: ${input.why}`, `Capability: ${c.capability}`, `Risk: ${c.risk}`];
  const argLines = approvalArgumentLines(input);

  return {
    title: cut(title, TITLE_MAX),
    description: cut([...lines, ...argLines].join('\n'), DESCRIPTION_MAX),
    impact: impactFor(c.risk),
    severity: severityFor(c.risk, input.hardRule === true),
  };
}

/**
 * SPEC §6.4 argument lines: command arguments first (whole command, cut to
 * 240), then the others by name (cut to 80), at most 5, secret values hidden.
 * Also sent as `meta.args` of a LumoAuth approval (§7.5).
 */
export function approvalArgumentLines(input: Pick<ApprovalTextInput, 'args' | 'commandArgs'>): string[] {
  const args = input.args ?? {};
  const commandNames = (input.commandArgs ?? []).filter((n) => Object.hasOwn(args, n) && args[n] !== undefined);
  const others = Object.keys(args)
    .filter((n) => !commandNames.includes(n) && args[n] !== undefined)
    .sort(compareCodePoints);
  const argLines: string[] = [];
  for (const name of [...commandNames, ...others]) {
    if (argLines.length >= MAX_ARG_LINES) break;
    const shownName = displayText(name);
    if (HIDDEN_NAME.test(name)) {
      argLines.push(`${shownName}: [hidden]`);
      continue;
    }
    const limit = commandNames.includes(name) ? COMMAND_MAX : VALUE_MAX;
    argLines.push(`${shownName}: ${cut(displayText(valueText(args[name])), limit)}`);
  }
  return argLines;
}
