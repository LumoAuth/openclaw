import { register } from "./plugin.js";
const plugin = {
    id: 'lumoauth',
    name: 'LumoAuth Guard',
    description: 'Checks every tool call before it runs: allowed, sent to you for approval, or blocked, with the policy held in LumoAuth.',
    register(api) {
        register(api);
    },
};
export default plugin;
export { Guard } from "./guard.js";
export { classify } from "./core/classify.js";
export { decide } from "./core/decide.js";
export { evaluateHardRules } from "./core/hard-rules.js";
export { covers, anyCovers, normalizeCapability } from "./core/capability.js";
export { canonicalJson, argumentsSha256 } from "./core/canonical-json.js";
