import type { OpenClawPluginApiLike, PluginLogger } from '../../src/host/openclaw-types.ts';

export interface MockApi extends OpenClawPluginApiLike {
  hooks: Map<string, { handler: (...a: any[]) => any; opts: any }>;
  commands: any[];
  services: any[];
  collectors: any[];
  clis: { registrar: any; opts: any }[];
  logs: { level: string; message: string }[];
  writes: any[];
  hook(name: string): (...a: any[]) => any;
}

/** A stand-in for OpenClaw's plugin API (the SDK's test helpers are not published). */
export function mockApi(opts: { mode?: string; config?: any; stateDir?: string; withRuntime?: boolean } = {}): MockApi {
  const logs: { level: string; message: string }[] = [];
  const logger: PluginLogger = {
    debug: (m) => void logs.push({ level: 'debug', message: m }),
    info: (m) => void logs.push({ level: 'info', message: m }),
    warn: (m) => void logs.push({ level: 'warn', message: m }),
    error: (m) => void logs.push({ level: 'error', message: m }),
  };
  const config = opts.config ?? {};
  const writes: any[] = [];
  const api: MockApi = {
    id: 'lumoauth',
    registrationMode: opts.mode ?? 'full',
    config,
    logger,
    hooks: new Map(),
    commands: [],
    services: [],
    collectors: [],
    clis: [],
    logs,
    writes,
    on(name, handler, o) {
      api.hooks.set(name, { handler, opts: o });
    },
    registerCommand(c) {
      api.commands.push(c);
    },
    registerService(s) {
      api.services.push(s);
    },
    registerSecurityAuditCollector(c) {
      api.collectors.push(c);
    },
    registerCli(registrar, o) {
      api.clis.push({ registrar, opts: o });
    },
    hook(name: string) {
      const h = api.hooks.get(name);
      if (!h) throw new Error(`hook ${name} not registered`);
      return h.handler;
    },
  };
  if (opts.withRuntime !== false) {
    api.runtime = {
      config: {
        current: () => config,
        mutateConfigFile: async (params) => {
          writes.push(params.afterWrite);
          await params.mutate(config);
        },
      },
      state: { resolveStateDir: () => opts.stateDir ?? '' },
    };
  }
  return api;
}
