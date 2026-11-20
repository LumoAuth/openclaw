import { anyCovers } from './capability.ts';
import type { Risk } from './catalog.ts';

export type ApprovalsMode = 'auto' | 'lumoauth' | 'host' | 'off';

export interface DecisionConfig {
  approvals: ApprovalsMode;
  onUngranted: 'ask' | 'block';
  taint: { enabled: boolean; windowSeconds: number; escalate: string[] };
  refreshSeconds: number;
  offlineGraceSeconds: number;
}

export interface SnapshotView {
  status: string;
  ageSeconds: number;
  capabilities: readonly string[];
}

export interface DecisionInput {
  classification: {
    capability: string;
    risk: Risk;
    egress?: boolean;
    persistsInstructions?: boolean;
  };
  hardRule: 'deny' | 'approve' | null;
  state: { locked: boolean; setUp: boolean };
  /** null: no snapshot. */
  snapshot: SnapshotView | null;
  tainted: boolean;
  config: DecisionConfig;
  /**
   * Server mode (§6.2): the Ask API's answer for the capability; undefined
   * means "use the snapshot" (local mode, or the Ask API was unavailable).
   */
  serverAllowed?: boolean | undefined;
}

export type ReasonCode =
  | 'locked'
  | 'not_set_up'
  | 'hard_rule'
  | 'hard_rule_approve'
  | 'snapshot_unavailable'
  | 'agent_inactive'
  | 'granted'
  | 'tainted'
  | 'not_granted'
  | 'approvals_off';

export interface Decision {
  outcome: 'allow' | 'block' | 'approve';
  reason: ReasonCode;
  /** Receipt decision for a block (SPEC §7.4). */
  receiptDecision?: 'blocked' | 'denied';
}

/** Reason texts (contract/vectors/decide.json). */
export const REASON_TEXT: Record<ReasonCode, string> = {
  locked: 'Locked by the owner',
  not_set_up: 'LumoAuth Guard is not set up',
  hard_rule: 'Protected by a rule that cannot be changed',
  hard_rule_approve: 'Touches something protected',
  snapshot_unavailable: "LumoAuth cannot confirm this agent's permissions",
  agent_inactive: 'The agent is not active in LumoAuth',
  granted: 'Granted',
  tainted: 'After the agent read untrusted content',
  not_granted: 'Not granted to this agent',
  approvals_off: 'Needs approval, and approvals are switched off',
};

const BLOCKED: ReadonlySet<ReasonCode> = new Set(['locked', 'not_set_up', 'hard_rule', 'snapshot_unavailable', 'agent_inactive']);

function block(reason: ReasonCode): Decision {
  return { outcome: 'block', reason, receiptDecision: BLOCKED.has(reason) ? 'blocked' : 'denied' };
}

function approval(reason: ReasonCode, config: DecisionConfig): Decision {
  if (config.approvals === 'off') return block('approvals_off');
  return { outcome: 'approve', reason };
}

/**
 * SPEC §6.1, up to the choice of approval channel. One deliberate reading:
 * the snapshot check (step 4) also runs before a hard-rule approval, so that
 * suspending the agent in LumoAuth stops every call (§1, kill switch).
 */
export function decide(input: DecisionInput): Decision {
  const { config } = input;
  if (input.state.locked) return block('locked');
  if (!input.state.setUp) return block('not_set_up');
  if (input.hardRule === 'deny') return block('hard_rule');

  const snap = input.snapshot;
  if (!snap || !(snap.ageSeconds <= config.refreshSeconds + config.offlineGraceSeconds)) return block('snapshot_unavailable');
  if (snap.status !== 'active') return block('agent_inactive');

  if (input.hardRule === 'approve') return approval('hard_rule_approve', config);

  const c = input.classification;
  const granted = input.serverAllowed ?? anyCovers(snap.capabilities, c.capability);
  if (granted) {
    if (input.tainted && config.taint.enabled) {
      const esc = config.taint.escalate;
      if (esc.includes(c.risk) || (esc.includes('egress') && c.egress === true) || c.persistsInstructions === true) {
        return approval('tainted', config);
      }
    }
    return { outcome: 'allow', reason: 'granted' };
  }
  if (config.onUngranted === 'block') return block('not_granted');
  return approval('not_granted', config);
}
