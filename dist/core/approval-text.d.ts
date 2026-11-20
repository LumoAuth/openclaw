import type { Risk } from './catalog.ts';
export type Impact = 'low' | 'medium' | 'high' | 'critical';
export type Severity = 'info' | 'warning' | 'critical';
export declare const TITLE_MAX = 80;
export declare const DESCRIPTION_MAX = 480;
export interface ApprovalText {
    title: string;
    description: string;
    impact: Impact;
    severity: Severity;
}
export declare function impactFor(risk: Risk): Impact;
export declare function severityFor(risk: Risk, hardRule: boolean): Severity;
/** Cut to `max` code points: the first max-1 and '…'. */
export declare function cut(text: string, max: number): string;
/**
 * Make model-chosen text safe to show a person: newlines become '⏎', and
 * other control characters, bidirectional overrides and zero-width
 * characters become U+FFFD (they could hide or reorder what is shown).
 */
export declare function displayText(text: string): string;
export interface ApprovalTextInput {
    classification: {
        tool: string;
        capability: string;
        risk: Risk;
        server?: string | null;
        mcpTool?: string | null;
    };
    args: Record<string, unknown>;
    /** Names of the tool's command arguments (catalog commandArgs). */
    commandArgs?: readonly string[] | undefined;
    why: string;
    hardRule?: boolean;
}
/** SPEC §6.4: title and description, built only from the classification and the arguments. */
export declare function approvalText(input: ApprovalTextInput): ApprovalText;
/**
 * SPEC §6.4 argument lines: command arguments first (whole command, cut to
 * 240), then the others by name (cut to 80), at most 5, secret values hidden.
 * Also sent as `meta.args` of a LumoAuth approval (§7.5).
 */
export declare function approvalArgumentLines(input: Pick<ApprovalTextInput, 'args' | 'commandArgs'>): string[];
