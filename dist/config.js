import { RISKS } from "./core/catalog.js";
export const DEFAULTS = {
    preset: 'assistant',
    decisionMode: 'local',
    approvals: 'auto',
    onUngranted: 'ask',
    taint: { enabled: true, windowSeconds: 1800, escalate: ['external'] },
    refreshSeconds: 60,
    offlineGraceSeconds: 300,
    receipts: true,
    rememberApprovals: true,
};
const TAINT_ESCALATE = new Set([...RISKS, 'egress']);
function str(v) {
    return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
}
export function isHttpsUrl(v) {
    try {
        return new URL(v).protocol === 'https:';
    }
    catch {
        return false;
    }
}
/**
 * Validate a parsed config.json. Unknown keys are ignored; a value out of
 * range falls back to its default and is listed in `issues`.
 */
export function parseConfig(raw) {
    const issues = [];
    if (!raw || typeof raw !== 'object' || Array.isArray(raw))
        return { config: null, issues, error: 'config.json is not a JSON object' };
    const r = raw;
    const baseUrl = str(r.baseUrl)?.replace(/\/+$/, '');
    const orgId = str(r.orgId);
    const agentId = str(r.agentId);
    const keyId = str(r.keyId);
    const issuer = str(r.issuer) ?? (baseUrl && orgId ? `${baseUrl}/orgs/${orgId}/api/v1` : undefined);
    const tokenEndpoint = str(r.tokenEndpoint) ?? (issuer ? `${issuer}/oauth/token` : undefined);
    const missing = Object.entries({ baseUrl, orgId, agentId, keyId, issuer, tokenEndpoint })
        .filter(([, v]) => !v)
        .map(([k]) => k);
    if (missing.length)
        return { config: null, issues, error: `config.json is missing ${missing.join(', ')}` };
    for (const [k, v] of Object.entries({ baseUrl, tokenEndpoint })) {
        if (!isHttpsUrl(v))
            return { config: null, issues, error: `config.json ${k} must be an https URL` };
    }
    const pick = (key, ok, fallback) => {
        if (!(key in r) || r[key] === undefined)
            return fallback;
        if (ok(r[key]))
            return r[key];
        issues.push(`${key}: ${JSON.stringify(r[key])} is not valid; using ${JSON.stringify(fallback)}`);
        return fallback;
    };
    const oneOf = (values) => (v) => typeof v === 'string' && values.includes(v);
    const intIn = (min, max) => (v) => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
    const bool = (v) => typeof v === 'boolean';
    const pathList = (v) => Array.isArray(v) && v.length <= 200 && v.every((x) => typeof x === 'string' && x.trim() !== '');
    let taint = { ...DEFAULTS.taint, escalate: [...DEFAULTS.taint.escalate] };
    if (r.taint !== undefined) {
        const t = r.taint;
        if (!t || typeof t !== 'object' || Array.isArray(t)) {
            issues.push('taint: not an object; using the defaults');
        }
        else {
            const enabled = t.enabled === undefined ? true : t.enabled;
            const windowSeconds = t.windowSeconds === undefined ? 1800 : t.windowSeconds;
            const escalate = t.escalate === undefined ? DEFAULTS.taint.escalate : t.escalate;
            taint = {
                enabled: bool(enabled) ? enabled : (issues.push('taint.enabled: not a boolean; using true'), true),
                windowSeconds: intIn(60, 86_400)(windowSeconds)
                    ? windowSeconds
                    : (issues.push(`taint.windowSeconds: ${JSON.stringify(windowSeconds)} is out of range (60-86400); using 1800`), 1800),
                escalate: Array.isArray(escalate) && escalate.every((x) => typeof x === 'string' && TAINT_ESCALATE.has(x))
                    ? [...escalate]
                    : (issues.push(`taint.escalate: ${JSON.stringify(escalate)} is not a list of risks; using ["external"]`), [...DEFAULTS.taint.escalate]),
            };
        }
    }
    const config = {
        version: 1,
        baseUrl: baseUrl,
        orgId: orgId,
        agentId: agentId,
        issuer: issuer,
        tokenEndpoint: tokenEndpoint,
        keyId: keyId,
        ownerUserId: str(r.ownerUserId) ?? null,
        canActOnBehalfOfUsers: r.canActOnBehalfOfUsers === true,
        preset: str(r.preset) ?? DEFAULTS.preset,
        decisionMode: pick('decisionMode', oneOf(['local', 'server']), DEFAULTS.decisionMode),
        approvals: pick('approvals', oneOf(['auto', 'lumoauth', 'host', 'off']), DEFAULTS.approvals),
        onUngranted: pick('onUngranted', oneOf(['ask', 'block']), DEFAULTS.onUngranted),
        taint,
        refreshSeconds: pick('refreshSeconds', intIn(30, 600), DEFAULTS.refreshSeconds),
        offlineGraceSeconds: pick('offlineGraceSeconds', intIn(0, 3600), DEFAULTS.offlineGraceSeconds),
        receipts: pick('receipts', bool, DEFAULTS.receipts),
        rememberApprovals: pick('rememberApprovals', bool, DEFAULTS.rememberApprovals),
        extraProtectedPaths: pick('extraProtectedPaths', pathList, []),
        allowPaths: pick('allowPaths', pathList, []),
    };
    const agentUrl = str(r.agentUrl);
    if (agentUrl && isHttpsUrl(agentUrl))
        config.agentUrl = agentUrl;
    const name = str(r.name);
    if (name)
        config.name = name;
    const enrolledAt = str(r.enrolledAt);
    if (enrolledAt)
        config.enrolledAt = enrolledAt;
    return { config, issues };
}
/** The agent's page in LumoAuth (where the owner grants capabilities). */
export function agentPortalUrl(config) {
    return config.agentUrl ?? `${config.baseUrl}/orgs/${encodeURIComponent(config.orgId)}/portal/agents/${encodeURIComponent(config.agentId)}`;
}
