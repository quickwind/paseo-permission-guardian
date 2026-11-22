export type GuardianMode = "off" | "shadow" | "act";

export type TimelineVerbosity = "off" | "notable" | "all";

export type Shell = "bash" | "pwsh5" | "pwsh7" | "cmd" | "argv";

export type HostOs = "windows" | "darwin" | "linux";

export type ActionKind =
  | "exec"
  | "read"
  | "edit"
  | "delete"
  | "fetch"
  | "mcp"
  | "plan"
  | "question"
  | "mode"
  | "other";

export type RiskLevel = "L0" | "L1" | "L2" | "L3";

export type GuardianVerdict = "allow" | "ask" | "deny";

export type ResolutionActor = "plugin" | "human" | "unknown";

export type AgreementOutcome =
  | "pending"
  | "agree"
  | "false_allow"
  | "false_deny"
  | "plugin_ask_human_allow"
  | "plugin_ask_human_deny"
  | "unknown";

export type EffectTagName =
  | "read"
  | "read_secret"
  | "write_worktree"
  | "write_outside"
  | "write_protected"
  | "delete_worktree"
  | "delete_outside"
  | "exec_project"
  | "exec_inline"
  | "exec_network_sourced"
  | "pkg_install"
  | "net_read"
  | "net_egress"
  | "vcs_remote"
  | "infra_read"
  | "infra_mutate"
  | "privilege"
  | "system_destructive"
  | "opaque";

export interface EffectTag {
  tag: EffectTagName;
  layer: number;
  target?: string;
  reversibility?: "reversible" | "irreversible";
  recursive?: boolean;
  pluginSelf?: boolean;
  detail?: string;
}

export interface ActionHost {
  os: HostOs;
  wsl?: {
    distro: string;
    user?: string;
  };
}

export interface ActionExec {
  shell: Shell;
  source: string;
}

export interface ActionUrl {
  href: string;
  method?: string;
  hasBody?: boolean;
}

export interface ActionMcp {
  server: string;
  tool: string;
  args: unknown;
}

export interface Action {
  provider: string;
  agentId: string;
  requestId: string;
  kind: ActionKind;
  toolName: string;
  host: ActionHost;
  cwd: string;
  worktreeRoot?: string;
  exec?: ActionExec;
  paths?: string[];
  url?: ActionUrl;
  mcp?: ActionMcp;
  sandboxBypass?: boolean;
  raw?: unknown;
}

export interface GuardianDecision {
  level: RiskLevel;
  verdict: GuardianVerdict;
  reasons: string[];
  effects?: EffectTag[];
  opaqueReasons?: string[];
  neverAutoAnswer?: boolean;
}

export interface AuditResolution {
  behavior: "allow" | "deny";
  selectedActionId?: string;
  message?: string;
  resolvedAt: string;
  actor: ResolutionActor;
}

export interface AuditRecord {
  version: 1;
  pluginVersion: string;
  requestId: string;
  agentId: string;
  provider: string;
  mode: GuardianMode;
  requestedAt?: string;
  latencyMs?: number;
  normalizedBy?: string;
  warnings?: string[];
  action?: Action;
  decision?: GuardianDecision;
  resolution?: AuditResolution;
  agreement: AgreementOutcome;
  outOfOrder?: boolean;
  offeredActions?: OfferedAction[];
  contextSnapshot?: ContextSnapshot;
  actOutcome?: ActOutcome;
}

export interface AuditMetricsSummary {
  totalRequests: number;
  reconciledCount: number;
  pendingCount: number;
  wouldAllowCount: number;
  wouldAskCount: number;
  wouldDenyCount: number;
  humanAllowCount: number;
  humanDenyCount: number;
  falseAllowCount: number;
  falseDenyCount: number;
  agreementCount: number;
  outOfOrderCount: number;
  lastUpdatedAt: string | null;
}

export interface GuardianStatusSnapshot {
  pluginVersion: string;
  mode: GuardianMode;
  effectiveMode: "off" | "shadow" | "act";
  dataDir: string;
  metrics: AuditMetricsSummary;
  gate: GateStatus;
}

export type GateState =
  | "replaying"
  | "unavailable"
  | "failed_false_allow"
  | "collecting"
  | "passed"
  | "latched"
  | "suspended";

/** `sent` is written at mark time (before the send); a later `after` replaces it. */
export type ActOutcome = "sent" | "answered" | "lost_race" | "unconfirmed" | "error" | "skipped";

export interface OfferedAction {
  id: string;
  behavior: "allow" | "deny";
}

export interface ContextSnapshot {
  secretTaint: boolean;
  untrustedTaint: boolean;
  modifiedEntrypoints: string[];
  modifiedFiles: string[];
  modifiedFilesTruncated: boolean;
}

export interface GateEntry {
  requestId: string;
  requestedAt?: string;
  command?: string;
  effects: string[];
  kind: "false_allow" | "orphan_deny" | "corrupt_line" | "unevaluable_deny";
  key: string;
}

export interface GateStatus {
  state: GateState;
  reason: string;
  samples: number;
  minSamples: number;
  falseAllowCount: number;
  falseDenyCount: number;
  entries: GateEntry[];
  unconfirmedCount: number;
  lastReplayAt: string | null;
  fingerprint: string;
  override: { valid: boolean; accepted: boolean; acceptedAt: string | null };
  latched: boolean;
  suspended: boolean;
}

/** Temporary placeholder until the gate is wired in (Task 8). */
export function emptyGateStatus(): GateStatus {
  return {
    state: "collecting",
    reason: "gate_not_initialized",
    samples: 0,
    minSamples: 200,
    falseAllowCount: 0,
    falseDenyCount: 0,
    entries: [],
    unconfirmedCount: 0,
    lastReplayAt: null,
    fingerprint: "",
    override: { valid: false, accepted: false, acceptedAt: null },
    latched: false,
    suspended: false,
  };
}
