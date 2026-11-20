// Conformance: every contract vector that applies to OpenClaw or is host-neutral.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { approvalText } from '../src/core/approval-text.ts';
import { anyCovers, covers, normalizeCapability } from '../src/core/capability.ts';
import { findCatalogTool, loadContract } from '../src/core/catalog.ts';
import { classify } from '../src/core/classify.ts';
import { decide, REASON_TEXT, type DecisionConfig } from '../src/core/decide.ts';
import { compileShellRules, evaluateHardRules } from '../src/core/hard-rules.ts';
import { mcpRisk } from '../src/core/mcp-risk.ts';
import { buildPathRules } from '../src/core/paths.ts';
import { loadVector, vectorEnv } from './helpers/env.ts';

const contract = loadContract();
const env = vectorEnv();
const rules = buildPathRules(env);
const shell = compileShellRules(rules, env);

describe('vectors/agent-capabilities.json', () => {
  const v = loadVector('agent-capabilities.json');
  for (const c of v.normalize) {
    test(`normalize ${JSON.stringify(c.input)}`, () => assert.equal(normalizeCapability(c.input), c.expected));
  }
  for (const c of v.covers) {
    test(`covers ${JSON.stringify(c.capability)} ${JSON.stringify(c.action)}`, () =>
      assert.equal(covers(c.capability, c.action), c.expected));
  }
  for (const c of v.any_covers) {
    test(`any_covers ${JSON.stringify(c.capabilities)} ${c.action}`, () =>
      assert.equal(anyCovers(c.capabilities, c.action), c.expected));
  }
});

describe('vectors/mcp-risk.json', () => {
  for (const c of loadVector('mcp-risk.json').cases) {
    test(`${c.server} ${c.tool}`, () => {
      assert.deepEqual(mcpRisk(contract.mcpVerbs, c.server, c.tool), { risk: c.risk, ingestsUntrusted: c.ingestsUntrusted });
    });
  }
});

describe('vectors/classify.json (host openclaw)', () => {
  for (const c of loadVector('classify.json').cases.filter((x: any) => x.host === 'openclaw')) {
    test(`${c.tool} ${JSON.stringify(c.args)}`, () => {
      const { classification } = classify(contract.host, contract.mcpVerbs, env, { toolName: c.tool, params: c.args });
      const expected = {
        tool: c.tool,
        ingestsUntrusted: false,
        persistsInstructions: false,
        egress: false,
        paths: [],
        command: null,
        server: null,
        mcpTool: null,
        hardRule: null,
        dispatchedBy: null,
        ...c.expected,
      };
      assert.deepEqual(classification, expected);
    });
  }
});

describe('vectors/hard-rules.json (host openclaw)', () => {
  for (const c of loadVector('hard-rules.json').cases.filter((x: any) => x.host === 'openclaw')) {
    test(c.id, () => {
      const classified = classify(contract.host, contract.mcpVerbs, env, {
        toolName: c.tool,
        params: c.args,
        derivedPaths: c.derivedPaths,
      });
      const r = evaluateHardRules(classified, rules, shell, env, { tainted: c.tainted === true });
      assert.equal(r.rule, c.expected.rule, `rule (got class ${r.class}: ${r.detail})`);
      if (c.expected.rule !== null) assert.equal(r.class, c.expected.class);
    });
  }
});

describe('vectors/decide.json', () => {
  const v = loadVector('decide.json');
  test('reason texts match', () => assert.deepEqual(REASON_TEXT, v.reasons));
  const defaults: DecisionConfig = {
    approvals: 'auto',
    onUngranted: 'ask',
    taint: { enabled: true, windowSeconds: 1800, escalate: ['external'] },
    refreshSeconds: 60,
    offlineGraceSeconds: 300,
  };
  for (const c of v.cases) {
    test(c.id, () => {
      const snapshot =
        c.snapshot === null ? null : { status: 'active', ageSeconds: 10, capabilities: [], ...(c.snapshot ?? {}) };
      const d = decide({
        classification: c.classification,
        hardRule: c.hardRule ?? null,
        state: { locked: false, setUp: true, ...(c.state ?? {}) },
        snapshot,
        tainted: c.tainted === true,
        config: { ...defaults, ...(c.config ?? {}) },
      });
      assert.equal(d.outcome, c.expected.outcome);
      assert.equal(d.reason, c.expected.reason);
      if (d.outcome === 'block') {
        const blocked = ['locked', 'not_set_up', 'hard_rule', 'snapshot_unavailable', 'agent_inactive'];
        assert.equal(d.receiptDecision, blocked.includes(d.reason) ? 'blocked' : 'denied');
      }
    });
  }
});

describe('vectors/approval-text.json', () => {
  for (const c of loadVector('approval-text.json').cases) {
    test(c.id, () => {
      const entry = findCatalogTool(contract.host, c.classification.tool);
      const t = approvalText({
        classification: c.classification,
        args: c.args,
        commandArgs: entry?.commandArgs,
        why: c.why,
        hardRule: c.hardRule === 'approve',
      });
      assert.deepEqual(t, c.expected);
    });
  }
});
