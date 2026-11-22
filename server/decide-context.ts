import type { Action } from "../shared/types.js";
import type { SessionState } from "./context/session.js";
import type { DecideOptions } from "./decide.js";
import { resolvePaseoHomeRoots, resolvePaseoSelfRoots, type WindowsPathContext } from "./paths/index.js";
import type { PwshHostProvider } from "./shell/pwsh-host.js";

/**
 * Single source of truth for the `decideAction` options used by BOTH the live permission path and
 * replay (spec §3.4). Anything that can change a live decision must be derived here so replay
 * evaluates under the same conditions; environment-derived inputs are also covered by the engine
 * fingerprint via `computeEnvDigest`.
 */
export interface DecideContextInput {
  action: Action;
  /** Live only: the agent's cwd (fallback worktree root). Replay passes undefined. */
  agentCwd?: string;
  /** Plugin data dir (plugin-self protected root). */
  dataDir: string;
  home: string;
  env: Record<string, string | undefined>;
  session?: SessionState;
  denyAsAsk: boolean;
  /** Replay: do not consult the current filesystem for realpaths. */
  skipHostRealpath?: boolean;
  pwshHostProvider?: PwshHostProvider;
  contextUnavailable?: boolean;
}

export type DecidePathCtxInput = Pick<
  DecideContextInput,
  "action" | "agentCwd" | "dataDir" | "home" | "env" | "skipHostRealpath"
>;

export function buildDecidePathCtx(input: DecidePathCtxInput): WindowsPathContext {
  const { action } = input;
  const pathCtx: WindowsPathContext = {
    cwd: action.cwd,
    worktreeRoot: action.worktreeRoot ?? input.agentCwd ?? action.cwd,
    pluginDataDir: input.dataDir,
    paseoRoots: resolvePaseoSelfRoots(input.env, input.home, input.dataDir),
    paseoHomeRoots: resolvePaseoHomeRoots(input.env, input.home),
  };
  if (input.skipHostRealpath) pathCtx.skipHostRealpath = true;
  return pathCtx;
}

export function buildDecideContext(input: DecideContextInput): DecideOptions {
  const options: DecideOptions = {
    pathCtx: buildDecidePathCtx(input),
    denyAsAsk: input.denyAsAsk,
    envSnapshot: input.env,
  };
  if (input.session) options.session = input.session;
  if (input.contextUnavailable !== undefined) options.contextUnavailable = input.contextUnavailable;
  if (input.pwshHostProvider) options.pwshHostProvider = input.pwshHostProvider;
  return options;
}
