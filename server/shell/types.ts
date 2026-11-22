import type { EffectTag, HostOs, Shell } from "../../shared/types.js";
import type { SessionState } from "../context/session.js";
import type { PwshHostMode } from "./pwsh.js";
import type { PwshHostProvider } from "./pwsh-host.js";

export interface RedirectionFact {
  operator: string;
  target: string;
  isWrite: boolean;
  isRead: boolean;
  dynamic?: boolean;
}

export interface AssignmentFact {
  name: string;
  value: string;
  standalone: boolean;
  depth: number;
  source: "prefix" | "standalone" | "declaration" | "wrapper";
}

export interface CommandFact {
  name: string;
  argv: string[];
  argvDynamic?: boolean[];
  rawText: string;
  redirections: RedirectionFact[];
  assignments: Record<string, string>;
  envReads: string[];
  pipelineId?: number;
  pipelineIndex?: number;
  depth: number;
  layer: Shell;
  effectiveCwd?: string;
  effectiveWorktree?: string;
  effectiveHome?: string;
  cwdChanged?: boolean;
  pwshCanonicalName?: string;
  pwshParams?: Record<string, string | boolean>;
  pwshArrayParams?: Record<string, string[]>;
  pwshExplicitWhatIf?: boolean;
  pwshPositionalArgs?: string[];
  pwshPositionalDynamic?: boolean[];
  pwshAllowVenvActivate?: boolean;
  preclassified?: boolean;
}

export interface PipelineFact {
  id: number;
  depth: number;
  commands: string[];
}

export interface LayerContext {
  os: HostOs;
  cwd: string;
  worktreeRoot?: string;
  home?: string;
  depth: number;
  pwshHost?: PwshHostMode;
  pwshHostProvider?: PwshHostProvider;
  allowPosixPwshHost?: boolean;
  pwshBinaryPath?: string;
  envSnapshot?: Record<string, string | undefined>;
  wsl?: {
    distro?: string;
    user?: string;
    automountRoot?: string;
  };
  session?: SessionState;
  pwdUncertain?: boolean;
  cdpathActive?: boolean;
  argvDynamic?: boolean[];
}

export interface LayerResult {
  commands: CommandFact[];
  pipelines: PipelineFact[];
  effects: EffectTag[];
  opaque: string[];
  assignments: AssignmentFact[];
  envReads: string[];
  unescapedSources?: string[];
  cwdChanged: boolean;
}
