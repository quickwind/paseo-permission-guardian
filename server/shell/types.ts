import type { EffectTag, HostOs, Shell } from "../../shared/types.js";

export interface RedirectionFact {
  operator: string;
  target: string;
  isWrite: boolean;
  isRead: boolean;
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
  rawText: string;
  redirections: RedirectionFact[];
  assignments: Record<string, string>;
  envReads: string[];
  pipelineId?: number;
  pipelineIndex?: number;
  depth: number;
  layer: Shell;
  cwdChanged?: boolean;
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
}

export interface LayerResult {
  commands: CommandFact[];
  pipelines: PipelineFact[];
  effects: EffectTag[];
  opaque: string[];
  assignments: AssignmentFact[];
  envReads: string[];
  cwdChanged: boolean;
}
