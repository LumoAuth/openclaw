import type { GuardHome } from '../guard-home.ts';
import type { HostPaths } from '../host/host-env.ts';
import type { CliContext, CommanderLike, OpenClawConfigLike } from '../host/openclaw-types.ts';
import {
  CliError,
  doctorCommand,
  lockCommand,
  resetCommand,
  setupCommand,
  statusCommand,
  unlockCommand,
  type CommandDeps,
  type HostConfigWriter,
} from './commands.ts';
import { processIo, type CliIo } from './io.ts';

export const CLI_DESCRIPTOR = {
  name: 'lumoauth',
  description: 'LumoAuth Guard: set up, check and lock the checks on every tool call',
  hasSubcommands: true,
};

export interface CliBindings {
  home: () => GuardHome;
  paths: (config: OpenClawConfigLike | undefined) => HostPaths;
  /** The host's config writer, looked up when a command runs (never during registration). */
  configWriter: () => HostConfigWriter | undefined;
  io?: () => CliIo;
}

async function run(io: CliIo, fn: () => Promise<unknown> | unknown): Promise<void> {
  try {
    await fn();
  } catch (err) {
    io.clearStatus();
    if (err instanceof CliError) io.err(`✗ ${err.message}`);
    else io.err(`✗ LumoAuth Guard: ${(err as Error)?.message ?? String(err)}`);
    io.setExitCode(1);
  }
}

/** `openclaw lumoauth setup|status|doctor|lock|unlock|reset` (SPEC §2, §8, §9). */
export function registerLumoauthCli(ctx: CliContext, bindings: CliBindings): void {
  const program: CommanderLike = ctx.program;
  const deps = (): CommandDeps => {
    const io = bindings.io?.() ?? processIo();
    return {
      io,
      home: bindings.home(),
      hostConfig: ctx.config,
      paths: bindings.paths(ctx.config),
      configWriter: bindings.configWriter(),
    };
  };

  const root = program.command('lumoauth').description(CLI_DESCRIPTOR.description);

  root
    .command('setup')
    .description('Connect this OpenClaw to LumoAuth: create a key, approve the agent in LumoAuth, and turn on the Guard')
    .option('--url <url>', 'LumoAuth dashboard address, e.g. https://app.lumoauth.dev/orgs/acme/portal')
    .option('--region <region>', 'us or eu (instead of --url; needs --org)')
    .option('--org <org>', 'organization id (when the URL does not contain /orgs/<org>)')
    .option('--preset <preset>', 'observer, assistant (default) or builder')
    .option('--approvals <mode>', 'auto (default), lumoauth, host or off')
    .option('--name <name>', 'agent name shown in LumoAuth (default: OpenClaw on <hostname>)')
    .option('--yes', 'do not ask questions; use the flags and defaults')
    .option('--force', 'enroll a new agent even when one is set up')
    .action(async (opts: Record<string, unknown>) => {
      const d = deps();
      await run(d.io, () =>
        setupCommand(d, {
          url: opts.url as string | undefined,
          region: opts.region as string | undefined,
          org: opts.org as string | undefined,
          preset: opts.preset as string | undefined,
          approvals: opts.approvals as string | undefined,
          name: opts.name as string | undefined,
          yes: opts.yes === true,
          force: opts.force === true,
        }),
      );
    });

  root
    .command('status')
    .description('Show the agent, its settings and capabilities, the connection to LumoAuth and recent decisions')
    .option('--json', 'print JSON')
    .option('--offline', 'do not contact LumoAuth')
    .action(async (opts: Record<string, unknown>) => {
      const d = deps();
      await run(d.io, () => statusCommand(d, { json: opts.json === true, offline: opts.offline === true }));
    });

  root
    .command('doctor')
    .description("Check the Guard and OpenClaw's own security settings (changes nothing)")
    .option('--json', 'print JSON')
    .option('--offline', 'do not contact LumoAuth')
    .action(async (opts: Record<string, unknown>) => {
      const d = deps();
      await run(d.io, () => doctorCommand(d, { json: opts.json === true, offline: opts.offline === true }));
    });

  root
    .command('lock')
    .description('Block every tool call on this machine until you unlock')
    .argument('[reason...]', 'why (shown in status)')
    .action(async (reason: string[] | undefined) => {
      const d = deps();
      await run(d.io, () => lockCommand(d, Array.isArray(reason) ? reason.join(' ') : ''));
    });

  root
    .command('unlock')
    .description('Remove the lock')
    .action(async () => {
      const d = deps();
      await run(d.io, () => unlockCommand(d));
    });

  root
    .command('reset')
    .description('Delete the agent key and the Guard configuration on this machine')
    .option('--yes', 'do not ask for confirmation')
    .action(async (opts: Record<string, unknown>) => {
      const d = deps();
      await run(d.io, () => resetCommand(d, { yes: opts.yes === true }));
    });
}
