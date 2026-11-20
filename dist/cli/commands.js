import { rmSync } from 'node:fs';
import { hostname } from 'node:os';
import { sanitizeName } from "../core/capability.js";
import { loadContract, RISKS } from "../core/catalog.js";
import { agentPortalUrl, DEFAULTS, isHttpsUrl } from "../config.js";
import { effectiveHookTimeoutMs, mayUseLumoAuthApprovals, runDoctor, worstLevel } from "../doctor.js";
import { DEFAULT_HOOK_TIMEOUT_MS, PLUGIN_ID, rfc3339 } from "../guard.js";
import { AgentClient } from "../lumoauth/agent-client.js";
import { generateAgentKey, jwkThumbprint, keyFingerprint, privateKeyToPem, publicJwk } from "../lumoauth/crypto.js";
import { EnrollmentError, pollEnrollment, startEnrollment } from "../lumoauth/enrollment.js";
import { defaultFetch } from "../lumoauth/http.js";
import { argumentsSha256 } from "../core/canonical-json.js";
import { packageVersion } from "../package-root.js";
import { levelMark, SPINNER, style } from "./io.js";
export const REGIONS = {
    us: 'https://app.lumoauth.dev',
    eu: 'https://eu.app.lumoauth.dev',
};
export class CliError extends Error {
}
/** A dashboard URL such as https://app.lumoauth.dev/orgs/acme/portal → base URL and organization. */
export function parseDashboardUrl(input) {
    let u;
    try {
        u = new URL(input.includes('://') ? input : `https://${input}`);
    }
    catch {
        throw new CliError(`"${input}" is not a URL. Copy the address of your LumoAuth dashboard, for example https://app.lumoauth.dev/orgs/acme/portal`);
    }
    if (u.protocol !== 'https:')
        throw new CliError('The LumoAuth URL must start with https://');
    if (u.username || u.password)
        throw new CliError('The LumoAuth URL must not contain a user name or password.');
    const m = /\/orgs\/([^/]+)/.exec(u.pathname);
    const orgId = m ? decodeURIComponent(m[1]) : undefined;
    if (orgId !== undefined && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(orgId))
        throw new CliError(`"${orgId}" is not an organization id.`);
    return { baseUrl: u.origin, orgId };
}
export function mcpServerNames(hostConfig) {
    const servers = hostConfig?.mcp?.servers;
    if (!servers || typeof servers !== 'object')
        return [];
    return Object.entries(servers)
        .filter(([, v]) => v?.enabled !== false)
        .map(([k]) => k)
        .slice(0, 100);
}
/** SPEC §8.1 step 5: every capability of the catalog, pre-ticked by the preset, plus mcp:<server>:<risk>:* per server. */
export function capabilityChecklist(presetName, servers) {
    const contract = loadContract();
    const preset = contract.presets.presets[presetName];
    if (!preset)
        throw new CliError(`Unknown preset "${presetName}". Use one of: ${Object.keys(contract.presets.presets).join(', ')}.`);
    const items = [];
    const seen = new Set();
    for (const tool of contract.host.tools) {
        if (seen.has(tool.capability))
            continue;
        seen.add(tool.capability);
        const meta = contract.capabilities.capabilities[tool.capability];
        items.push({
            scope: tool.capability,
            risk: meta?.risk ?? tool.risk,
            label: (meta?.label ?? `Use the ${tool.name} tool`).slice(0, 120),
            checked: preset.capabilities.includes(tool.capability),
        });
    }
    for (const cap of preset.capabilities) {
        if (seen.has(cap))
            continue;
        const meta = contract.capabilities.capabilities[cap];
        if (!meta)
            continue;
        seen.add(cap);
        items.push({ scope: cap, risk: meta.risk, label: meta.label.slice(0, 120), checked: true });
    }
    for (const server of servers) {
        const s = sanitizeName(server);
        for (const risk of RISKS) {
            if (items.length >= 200)
                break;
            const template = contract.capabilities.mcpRiskLabels[risk];
            if (!template)
                continue;
            items.push({ scope: `mcp:${s}:${risk}:*`, risk, label: template.replace('{server}', server).slice(0, 120), checked: preset.mcp.includes(risk) });
        }
    }
    return items.slice(0, 200);
}
function labelFor(cap) {
    const contract = loadContract();
    const meta = contract.capabilities.capabilities[cap];
    if (meta)
        return meta.label;
    const m = /^mcp:([^:]+):([^:]+):\*$/.exec(cap);
    if (m)
        return (contract.capabilities.mcpRiskLabels[m[2]] ?? `${m[1]}: tools`).replace('{server}', m[1]);
    if (cap === '*')
        return 'Everything (except what the Guard always protects)';
    return cap;
}
function clientFor(deps, config) {
    return new AgentClient({
        baseUrl: config.baseUrl,
        orgId: config.orgId,
        agentId: config.agentId,
        issuer: config.issuer,
        tokenEndpoint: config.tokenEndpoint,
        keyId: config.keyId,
        key: deps.home.readKey(),
        fetchFn: deps.fetchFn,
        now: deps.now,
        userAgent: `lumoauth-openclaw/${packageVersion()}`,
    });
}
export async function setupCommand(deps, opts) {
    const { io, home } = deps;
    const s = style(io);
    const interactive = io.isTTY && !opts.yes && !!io.prompt;
    const contract = loadContract();
    io.out(s.bold('LumoAuth Guard for OpenClaw'));
    io.out(s.dim('Every tool call your agent makes is checked before it runs: allowed, sent to you for approval, or blocked.'));
    io.out();
    const existing = home.readConfig();
    if (existing.config && home.hasKey() && !opts.force) {
        io.out(`${s.green('✓')} Already set up as agent ${s.bold(existing.config.agentId)} in ${existing.config.baseUrl}/orgs/${existing.config.orgId}.`);
        io.out(`  Run ${s.cyan('openclaw lumoauth status')} to check it, or ${s.cyan('openclaw lumoauth setup --force')} to enroll a new agent.`);
        return;
    }
    // Step 1: find LumoAuth.
    io.out(`${s.bold('Step 1 of 4')}  Find your LumoAuth organization`);
    let url = opts.url?.trim();
    if (!url && opts.region) {
        const base = REGIONS[opts.region.toLowerCase()];
        if (!base)
            throw new CliError(`Unknown region "${opts.region}". Use us or eu, or pass --url.`);
        url = opts.org ? `${base}/orgs/${opts.org}` : base;
    }
    if (!url && interactive) {
        url = await io.prompt('  Paste the address of your LumoAuth dashboard (for example https://app.lumoauth.dev/orgs/acme/portal): ');
    }
    if (!url)
        throw new CliError('Pass --url with the address of your LumoAuth dashboard, for example: openclaw lumoauth setup --url https://app.lumoauth.dev/orgs/acme/portal');
    const parsed = parseDashboardUrl(url);
    let orgId = opts.org?.trim() || parsed.orgId;
    if (!orgId && interactive)
        orgId = await io.prompt('  Organization id (the part after /orgs/ in the dashboard address): ');
    if (!orgId)
        throw new CliError('The URL does not name an organization. Use the dashboard address that contains /orgs/<organization>, or pass --org.');
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(orgId))
        throw new CliError(`"${orgId}" is not an organization id.`);
    const baseUrl = parsed.baseUrl;
    io.out(`  ${s.green('✓')} ${baseUrl}, organization ${s.bold(orgId)}`);
    io.out();
    // Step 2: inventory and choices.
    io.out(`${s.bold('Step 2 of 4')}  Choose what the agent may do without asking`);
    const servers = mcpServerNames(deps.hostConfig);
    const toolCount = contract.host.tools.length;
    io.out(`  ${s.green('✓')} OpenClaw: ${toolCount} built-in tools, ${servers.length} MCP server${servers.length === 1 ? '' : 's'}${servers.length ? ` (${servers.slice(0, 8).join(', ')}${servers.length > 8 ? ', …' : ''})` : ''}`);
    let preset = opts.preset?.trim().toLowerCase();
    const presetNames = Object.keys(contract.presets.presets);
    if (!preset && interactive) {
        io.out('  Presets:');
        presetNames.forEach((name, i) => io.out(`    ${i + 1}. ${contract.presets.presets[name].label}`));
        const answer = await io.prompt(`  Preset [${presetNames.indexOf(contract.presets.default) + 1}]: `);
        const n = Number.parseInt(answer, 10);
        preset = answer === '' ? contract.presets.default : Number.isInteger(n) && presetNames[n - 1] ? presetNames[n - 1] : answer.toLowerCase();
    }
    preset = preset || contract.presets.default;
    if (!contract.presets.presets[preset])
        throw new CliError(`Unknown preset "${preset}". Use one of: ${presetNames.join(', ')}.`);
    const approvals = (opts.approvals?.trim().toLowerCase() || 'auto');
    if (!['auto', 'lumoauth', 'host', 'off'].includes(approvals))
        throw new CliError('--approvals must be auto, lumoauth, host or off.');
    const checklist = capabilityChecklist(preset, servers);
    io.out(`  ${s.green('✓')} Preset ${s.bold(preset)}: ${checklist.filter((c) => c.checked).length} of ${checklist.length} capabilities ticked; approvals: ${approvals}`);
    io.out(s.dim('    You can change the ticks on the approval page, and later in LumoAuth.'));
    io.out();
    // Step 3: key.
    io.out(`${s.bold('Step 3 of 4')}  Create the agent's key`);
    const key = generateAgentKey();
    const jwk = publicJwk(key);
    const kid = jwkThumbprint(jwk);
    const fingerprint = keyFingerprint(kid);
    home.ensure();
    home.writeKey(privateKeyToPem(key));
    io.out(`  ${s.green('✓')} Key saved to ${home.keyPath} (only your user can read it; it never leaves this machine)`);
    io.out(`    Key fingerprint: ${s.bold(fingerprint)}`);
    io.out();
    // Step 4: enrollment.
    io.out(`${s.bold('Step 4 of 4')}  Approve the agent in LumoAuth`);
    const host = deps.hostname ?? hostname();
    const name = (opts.name?.trim() || `OpenClaw on ${host}`).slice(0, 100);
    const request = {
        name,
        host: 'openclaw',
        host_label: host.slice(0, 100),
        jwks: { keys: [{ ...jwk, kid, use: 'sig', alg: 'ES256' }] },
        capabilities: checklist,
        delegation: approvals === 'auto' || approvals === 'lumoauth',
        inventory: { tools: toolCount, mcp_servers: servers.map((n) => ({ name: n.slice(0, 64) })) },
    };
    const fetchFn = deps.fetchFn ?? defaultFetch;
    const ua = `lumoauth-openclaw/${packageVersion()}`;
    let start;
    try {
        start = await startEnrollment(fetchFn, baseUrl, orgId, request, ua);
    }
    catch (err) {
        throw new CliError(`LumoAuth did not start the enrollment: ${err.message}`);
    }
    if (start.key_fingerprint && start.key_fingerprint !== fingerprint) {
        throw new CliError(`LumoAuth reports key fingerprint ${start.key_fingerprint}, but this key is ${fingerprint}. Setup stopped; run it again.`);
    }
    io.out(`  Open this page, sign in, and approve:`);
    io.out(`    ${s.cyan(start.verification_uri_complete ?? start.verification_uri)}`);
    io.out(`  Check that the page shows code ${s.bold(start.user_code)} and key fingerprint ${s.bold(fingerprint)}.`);
    io.out(s.dim('  Approve only if you ran this command yourself just now.'));
    let frame = 0;
    let lastDot = 0;
    const now = deps.now ?? Date.now;
    let result;
    try {
        result = await pollEnrollment(fetchFn, baseUrl, orgId, start.enrollment_code, {
            interval: start.interval,
            expiresIn: start.expires_in,
            ...(deps.sleep ? { sleep: deps.sleep } : {}),
            now,
            userAgent: ua,
            onWait: (left) => {
                if (io.isTTY) {
                    const m = Math.floor(left / 60);
                    const sec = String(left % 60).padStart(2, '0');
                    io.status(`  ${SPINNER[frame++ % SPINNER.length]} Waiting for approval (${m}:${sec} left)`);
                }
                else if (now() - lastDot > 60_000 || lastDot === 0) {
                    lastDot = now();
                    io.out(`  … waiting for approval (${Math.ceil(left / 60)} min left)`);
                }
            },
        });
    }
    catch (err) {
        io.clearStatus();
        rmSync(home.keyPath, { force: true });
        if (err instanceof EnrollmentError) {
            if (err.code === 'access_denied')
                throw new CliError('The agent was denied in LumoAuth. Nothing was changed. Run setup again to retry.');
            if (err.code === 'expired_token')
                throw new CliError('The approval page was not used in time. Run setup again for a new code.');
        }
        throw new CliError(`Enrollment failed: ${err.message}`);
    }
    io.clearStatus();
    io.out(`  ${s.green('✓')} Approved: agent ${s.bold(result.agent_id)}`);
    io.out();
    // Write config.json.
    const config = {
        version: 1,
        baseUrl,
        orgId,
        agentId: result.agent_id,
        issuer: result.issuer,
        tokenEndpoint: result.token_endpoint,
        keyId: result.key_id || kid,
        ownerUserId: result.owner_user_id ?? null,
        canActOnBehalfOfUsers: result.can_act_on_behalf_of_users,
        preset,
        decisionMode: DEFAULTS.decisionMode,
        approvals,
        onUngranted: DEFAULTS.onUngranted,
        taint: { ...DEFAULTS.taint, escalate: [...DEFAULTS.taint.escalate] },
        refreshSeconds: DEFAULTS.refreshSeconds,
        offlineGraceSeconds: DEFAULTS.offlineGraceSeconds,
        receipts: DEFAULTS.receipts,
        rememberApprovals: DEFAULTS.rememberApprovals,
        extraProtectedPaths: [],
        allowPaths: [],
        ...(result.agent_url && isHttpsUrl(result.agent_url) ? { agentUrl: result.agent_url } : {}),
        name,
        enrolledAt: rfc3339(now()),
    };
    if (!isHttpsUrl(config.tokenEndpoint) || !isHttpsUrl(config.issuer)) {
        throw new CliError('LumoAuth answered with a token endpoint that is not https. Setup stopped.');
    }
    home.writeConfig(config);
    io.out(`${s.green('✓')} Saved ${home.configPath}`);
    // Configure OpenClaw.
    const needTimeout = mayUseLumoAuthApprovals(config) && effectiveHookTimeoutMs(deps.hostConfig) < 150_000;
    const commands = [`openclaw config set plugins.entries.${PLUGIN_ID}.enabled true`];
    if (mayUseLumoAuthApprovals(config))
        commands.push(`openclaw config set plugins.entries.${PLUGIN_ID}.hooks.timeouts.before_tool_call ${DEFAULT_HOOK_TIMEOUT_MS}`);
    let configured = false;
    if (deps.configWriter) {
        try {
            await deps.configWriter((draft) => {
                draft.plugins ??= {};
                draft.plugins.entries ??= {};
                const entry = (draft.plugins.entries[PLUGIN_ID] ??= {});
                entry.enabled = true;
                if (mayUseLumoAuthApprovals(config)) {
                    entry.hooks ??= {};
                    entry.hooks.timeouts ??= {};
                    const current = entry.hooks.timeouts.before_tool_call;
                    if (typeof current !== 'number' || current < 150_000)
                        entry.hooks.timeouts.before_tool_call = DEFAULT_HOOK_TIMEOUT_MS;
                }
            });
            configured = true;
            io.out(`${s.green('✓')} OpenClaw: plugin enabled${mayUseLumoAuthApprovals(config) ? ', hook timeout 180 s for LumoAuth approvals' : ''}`);
        }
        catch (err) {
            io.out(`${s.yellow('!')} OpenClaw's config could not be changed (${err.message}).`);
        }
    }
    if (!configured) {
        io.out(`${s.yellow('!')} Run these commands to finish:`);
        for (const c of commands)
            io.out(`    ${c}`);
    }
    else if (needTimeout) {
        io.out(s.dim('  Restart the gateway if it does not reload by itself: openclaw gateway restart'));
    }
    // Self-test.
    io.out();
    io.out(s.bold('Self-test'));
    let caps = result.capabilities;
    let selfTestOk = false;
    let selfTestError;
    try {
        const client = clientFor(deps, config);
        const me = await client.me();
        caps = Array.isArray(me.capabilities) ? me.capabilities.filter((c) => typeof c === 'string') : caps;
        io.out(`  ${s.green('✓')} Token (private_key_jwt + DPoP) and capability snapshot: agent ${me.identity?.status ?? 'unknown'}`);
        await client.reportToolCalls([
            { tool: 'lumoauth.selftest', decision: 'allowed', outcome: 'succeeded', arguments_sha256: argumentsSha256({}), occurred_at: rfc3339(now()) },
        ]);
        io.out(`  ${s.green('✓')} Audit receipt delivered (tool lumoauth.selftest)`);
        selfTestOk = true;
    }
    catch (err) {
        selfTestError = err.message;
        io.out(`  ${s.red('✗')} ${selfTestError}`);
        io.setExitCode(1);
    }
    io.out();
    io.out(s.bold(`Granted without asking (${caps.length})`));
    if (caps.length === 0)
        io.out(s.dim('  None: every tool call asks first.'));
    for (const c of caps.slice(0, 60))
        io.out(`  • ${c} ${s.dim(labelFor(c))}`);
    if (caps.length > 60)
        io.out(`  … and ${caps.length - 60} more`);
    io.out(s.dim('  Everything else asks you first. The Guard always protects its key, OpenClaw\'s configuration and your credential stores.'));
    const checks = await runDoctor({
        home,
        hostConfig: deps.hostConfig,
        paths: deps.paths,
        env: deps.env ?? process.env,
        live: false,
        lastKnown: selfTestOk ? { status: 'active' } : { error: selfTestError ?? 'self-test failed' },
    });
    io.out();
    printDoctorSummary(io, checks);
    io.out();
    io.out(`${s.green('Done.')} Check it any time with ${s.cyan('openclaw lumoauth status')}. Stop everything with ${s.cyan('openclaw lumoauth lock')}.`);
}
function printDoctorSummary(io, checks) {
    const s = style(io);
    const notOk = checks.filter((c) => c.level !== 'ok' && c.id !== 'guard.connectivity');
    if (!notOk.length) {
        io.out(`${s.bold('Doctor')}  ${s.green('✓')} All ${checks.length} checks passed.`);
        return;
    }
    io.out(`${s.bold('Doctor')}  ${notOk.length} suggestion${notOk.length === 1 ? '' : 's'} (details: openclaw lumoauth doctor)`);
    for (const c of notOk)
        io.out(`  ${levelMark(c.level, s)} ${c.finding}`);
}
export async function statusCommand(deps, opts) {
    const { io, home } = deps;
    const s = style(io);
    const loaded = home.readConfig();
    const config = loaded.config;
    const hasKey = home.hasKey();
    const lock = home.readLock();
    const gateway = home.readStatusReport();
    const nowMs = (deps.now ?? Date.now)();
    const gatewayFresh = gateway && Date.parse(gateway.updatedAt) > nowMs - 5 * 60_000;
    let live;
    if (config && hasKey && !opts.offline) {
        try {
            const me = await clientFor(deps, config).me();
            live = {
                ok: true,
                status: typeof me.identity?.status === 'string' ? me.identity.status : 'unknown',
                capabilities: Array.isArray(me.capabilities) ? me.capabilities.filter((c) => typeof c === 'string') : [],
            };
        }
        catch (err) {
            live = { ok: false, error: err.message };
        }
    }
    const report = {
        setUp: Boolean(config && hasKey),
        guardHome: home.dir,
        setupError: !config ? (loaded.error ?? (loaded.exists ? 'config.json cannot be used' : 'not set up')) : !hasKey ? 'agent-key.pem is missing' : null,
        locked: lock,
        agent: config
            ? {
                agentId: config.agentId,
                name: config.name ?? null,
                orgId: config.orgId,
                baseUrl: config.baseUrl,
                agentUrl: agentPortalUrl(config),
                keyId: config.keyId,
                keyFingerprint: keyFingerprint(config.keyId),
                ownerUserId: config.ownerUserId,
            }
            : null,
        settings: config
            ? {
                preset: config.preset,
                decisionMode: config.decisionMode,
                approvals: config.approvals,
                onUngranted: config.onUngranted,
                taint: config.taint,
                refreshSeconds: config.refreshSeconds,
                offlineGraceSeconds: config.offlineGraceSeconds,
                receipts: config.receipts,
                rememberApprovals: config.rememberApprovals,
                delegation: config.canActOnBehalfOfUsers,
            }
            : null,
        configIssues: loaded.issues,
        connectivity: live ?? null,
        hookTimeoutMs: effectiveHookTimeoutMs(deps.hostConfig),
        gateway: gateway
            ? {
                fresh: Boolean(gatewayFresh),
                updatedAt: gateway.updatedAt,
                snapshot: gateway.snapshot,
                lastError: gateway.lastError,
                serverModeIssue: gateway.serverModeIssue,
                receipts: gateway.receipts,
                taintedSessions: gateway.taintedSessions,
                waitingForApproval: Array.isArray(gateway.waitingForApproval) ? gateway.waitingForApproval : [],
                recent: gateway.recent,
            }
            : null,
    };
    if (opts.json) {
        io.out(JSON.stringify(report, null, 2));
        return report;
    }
    io.out(s.bold('LumoAuth Guard status'));
    if (!config || !hasKey) {
        io.out(`  ${s.red('✗')} Not set up${report.setupError && report.setupError !== 'not set up' ? ` (${report.setupError})` : ''}: OpenClaw blocks every tool call.`);
        io.out(`    Run ${s.cyan('openclaw lumoauth setup')}`);
        if (lock)
            io.out(`  ${s.yellow('!')} Locked since ${lock.at}${lock.reason ? `: ${lock.reason}` : ''}`);
        return report;
    }
    const row = (k, v) => io.out(`  ${k.padEnd(14)} ${v}`);
    row('Agent', `${config.name ? `${config.name} ` : ''}(${config.agentId})`);
    row('LumoAuth', `${config.baseUrl}, organization ${config.orgId}`);
    row('Agent page', agentPortalUrl(config));
    row('Key', `fingerprint ${keyFingerprint(config.keyId)}`);
    row('Preset', config.preset);
    row('Decisions', `${config.decisionMode}; not granted → ${config.onUngranted === 'ask' ? 'ask' : 'block'}; approvals ${config.approvals}`);
    row('Taint', config.taint.enabled ? `on, ${Math.round(config.taint.windowSeconds / 60)} min, escalates ${config.taint.escalate.join(', ')}` : 'off');
    row('Lock', lock ? s.red(`LOCKED since ${lock.at}${lock.reason ? `: ${lock.reason}` : ''} (openclaw lumoauth unlock)`) : 'off');
    for (const issue of loaded.issues)
        io.out(`  ${s.yellow('!')} config.json ${issue}`);
    if (live) {
        if (live.ok) {
            const active = live.status === 'active';
            row('LumoAuth', `${active ? s.green('connected') : s.red(`agent ${live.status}`)}; ${live.capabilities.length} capabilities`);
            for (const c of live.capabilities.slice(0, 40))
                io.out(`    • ${c} ${s.dim(labelFor(c))}`);
            if (live.capabilities.length > 40)
                io.out(`    … and ${live.capabilities.length - 40} more`);
            if (!active)
                io.setExitCode(1);
        }
        else {
            row('LumoAuth', s.red(live.error ?? 'error'));
            io.setExitCode(1);
        }
    }
    if (gateway) {
        io.out();
        io.out(`  ${s.bold('Last report from OpenClaw')} ${s.dim(`(process ${gateway.pid ?? '?'}, ${gateway.updatedAt}${gatewayFresh ? '' : '; it may not be running'})`)}`);
        const r = gateway.receipts ?? {};
        io.out(`    Receipts: ${r.sent ?? 0} sent, ${r.queued ?? 0} queued, ${r.pending ?? 0} running, ${r.dropped ?? 0} dropped${r.rejected ? `, ${r.rejected} refused` : ''}`);
        for (const w of Array.isArray(gateway.waitingForApproval) ? gateway.waitingForApproval : []) {
            io.out(`    ${s.yellow('…')} Waiting for approval ${w.where}: ${w.tool} (${w.capability}) since ${w.since}`);
        }
        if (gateway.lastError)
            io.out(`    ${s.yellow('!')} Last refresh failed: ${gateway.lastError.message}`);
        if (gateway.serverModeIssue)
            io.out(`    ${s.yellow('!')} ${gateway.serverModeIssue}`);
        const recent = Array.isArray(gateway.recent) ? gateway.recent.slice(0, 10) : [];
        if (recent.length) {
            io.out('    Recent decisions:');
            for (const d of recent)
                io.out(`      ${d.at}  ${String(d.decision).padEnd(8)} ${d.tool} ${s.dim(`${d.capability} · ${d.reason}`)}`);
        }
    }
    else {
        io.out(s.dim('  No report from OpenClaw yet (a running gateway writes one every 10 s).'));
    }
    return report;
}
// ---------------------------------------------------------------------------
// doctor
export async function doctorCommand(deps, opts) {
    const { io } = deps;
    const s = style(io);
    const checks = await runDoctor({
        home: deps.home,
        hostConfig: deps.hostConfig,
        paths: deps.paths,
        env: deps.env ?? process.env,
        live: !opts.offline,
        fetchFn: deps.fetchFn,
    });
    if (worstLevel(checks) === 'critical')
        io.setExitCode(1);
    if (opts.json) {
        io.out(JSON.stringify({ checks }, null, 2));
        return checks;
    }
    io.out(s.bold('LumoAuth Guard doctor'));
    for (const c of checks) {
        io.out(`  ${levelMark(c.level, s)} ${c.id.padEnd(27)} ${c.finding}`);
        if (c.fix && c.level !== 'ok')
            io.out(`    ${' '.repeat(27)} ${s.dim(`Fix: ${c.fix}`)}`);
    }
    const counts = checks.reduce((m, c) => ({ ...m, [c.level]: (m[c.level] ?? 0) + 1 }), {});
    io.out();
    io.out(`  ${counts.critical ?? 0} critical, ${counts.warn ?? 0} warnings, ${counts.info ?? 0} notes, ${counts.ok ?? 0} ok. Doctor changes nothing.`);
    return checks;
}
// ---------------------------------------------------------------------------
// lock, unlock, reset
export function lockCommand(deps, reason) {
    const s = style(deps.io);
    deps.home.lock(reason || 'locked by the owner');
    deps.io.out(`${s.red('Locked.')} OpenClaw blocks every tool call until you run ${s.cyan('openclaw lumoauth unlock')}.`);
}
export function unlockCommand(deps) {
    const s = style(deps.io);
    if (deps.home.unlock())
        deps.io.out(`${s.green('Unlocked.')} Tool calls are checked as usual again.`);
    else
        deps.io.out('Not locked.');
}
export async function resetCommand(deps, opts) {
    const { io, home } = deps;
    const s = style(io);
    const loaded = home.readConfig();
    if (!opts.yes) {
        if (!io.isTTY || !io.prompt)
            throw new CliError('Reset deletes the agent key and the Guard configuration. Pass --yes to confirm.');
        const answer = await io.prompt('Delete the agent key and the Guard configuration on this machine? Type "reset" to confirm: ');
        if (answer !== 'reset') {
            io.out('Nothing was changed.');
            return;
        }
    }
    for (const p of [home.keyPath, home.configPath, home.statusPath])
        rmSync(p, { force: true });
    io.out(`${s.green('✓')} Deleted the agent key and the configuration in ${home.dir}.`);
    if (home.isLocked())
        io.out(`  The lock stays on. Remove it with ${s.cyan('openclaw lumoauth unlock')} after the next setup.`);
    if (loaded.config) {
        io.out(`  The agent ${s.bold(loaded.config.agentId)} still exists in LumoAuth. Delete it there if you no longer need it:`);
        io.out(`    ${agentPortalUrl(loaded.config)}`);
    }
    io.out(`  OpenClaw now blocks every tool call. Run ${s.cyan('openclaw lumoauth setup')} again, or remove the plugin: openclaw plugins uninstall ${PLUGIN_ID}`);
}
