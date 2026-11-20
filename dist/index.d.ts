/**
 * @lumoauth/openclaw — LumoAuth Guard for OpenClaw (plugin id `lumoauth`).
 *
 * Every tool call that an OpenClaw agent makes is classified and allowed,
 * sent to a person for approval, or blocked, outside the model, with the
 * policy held in LumoAuth. The contract is SPEC.md of the agent-guard
 * repository; this package vendors its catalog and test vectors.
 *
 * OpenClaw loads the default export: a plain plugin definition with a
 * synchronous register(api). No runtime dependency on OpenClaw.
 */
import type { OpenClawPluginApiLike } from './host/openclaw-types.ts';
declare const plugin: {
    id: string;
    name: string;
    description: string;
    register(api: OpenClawPluginApiLike): void;
};
export default plugin;
export { Guard } from './guard.ts';
export { classify } from './core/classify.ts';
export { decide } from './core/decide.ts';
export { evaluateHardRules } from './core/hard-rules.ts';
export { covers, anyCovers, normalizeCapability } from './core/capability.ts';
export { canonicalJson, argumentsSha256 } from './core/canonical-json.ts';
