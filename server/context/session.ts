import type { AgentTimelineItem } from "@getpaseo/protocol/agent-types";
import { classifyPosixPath, isBuildOrScriptEntrypoint, type PathContext } from "../paths/index.js";

export interface SessionState {
  agentId: string;
  untrustedTaint: boolean;
  secretTaint: boolean;
  taintEpoch: number;
  worktreeMutationEpoch: number;
  scopeGrantVersion: number;
  modifiedFiles: Set<string>;
  modifiedEntrypoints: Set<string>;
  seenCallIds: Set<string>;
}

export interface TimelineFetcher {
  (agentId: string): Promise<AgentTimelineItem[]>;
}

const DEFAULT_TRUSTED_DOMAINS = new Set([
  "registry.npmjs.org",
  "pypi.org",
  "files.pythonhosted.org",
  "crates.io",
  "docs.rs",
  "pkg.go.dev",
  "developer.mozilla.org",
  "nodejs.org",
]);

function extractHostname(urlStr: string): string | null {
  try {
    return new URL(urlStr).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function isTrustedDomain(urlStr: string, trustedDomains: Set<string>): boolean {
  const host = extractHostname(urlStr);
  if (!host) return false;
  if (trustedDomains.has(host)) return true;
  for (const domain of trustedDomains) {
    if (domain.startsWith("*.") && host.endsWith(domain.slice(1))) {
      return true;
    }
  }
  return false;
}

const SENSITIVE_SHELL_SECRET_REGEX =
  /\b(?:env|printenv|export\s+-p)\b|\$[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)\b/i;

export class SessionContextStore {
  private readonly sessions = new Map<string, SessionState>();
  private readonly trustedDomains: Set<string>;

  constructor(extraTrustedDomains: string[] = []) {
    this.trustedDomains = new Set([
      ...DEFAULT_TRUSTED_DOMAINS,
      ...extraTrustedDomains.map((d) => d.toLowerCase()),
    ]);
  }

  getOrCreate(agentId: string): SessionState {
    let state = this.sessions.get(agentId);
    if (!state) {
      state = {
        agentId,
        untrustedTaint: false,
        secretTaint: false,
        taintEpoch: 0,
        worktreeMutationEpoch: 0,
        scopeGrantVersion: 0,
        modifiedFiles: new Set(),
        modifiedEntrypoints: new Set(),
        seenCallIds: new Set(),
      };
      this.sessions.set(agentId, state);
    }
    return state;
  }

  markUntrustedTaint(agentId: string): void {
    const state = this.getOrCreate(agentId);
    if (!state.untrustedTaint) {
      state.untrustedTaint = true;
      state.taintEpoch += 1;
    }
  }

  markSecretTaint(agentId: string): void {
    const state = this.getOrCreate(agentId);
    if (!state.secretTaint) {
      state.secretTaint = true;
      state.taintEpoch += 1;
    }
  }

  recordFileModification(agentId: string, filePath: string, pathCtx: PathContext): void {
    const state = this.getOrCreate(agentId);
    const classified = classifyPosixPath(filePath, pathCtx);
    state.modifiedFiles.add(classified.realPath);
    state.worktreeMutationEpoch += 1;

    if (isBuildOrScriptEntrypoint(classified.realPath, pathCtx.worktreeRoot ?? pathCtx.cwd)) {
      state.modifiedEntrypoints.add(classified.realPath);
    }
  }

  /**
   * Incrementally sync same-turn tool calls from the agent timeline (ADR-0002)
   * so provider-auto-approved Read / Edit / WebFetch calls are reflected immediately.
   */
  async syncFromTimeline(
    agentId: string,
    pathCtx: PathContext,
    fetchTimeline?: TimelineFetcher,
  ): Promise<SessionState> {
    const state = this.getOrCreate(agentId);
    if (!fetchTimeline) {
      return state;
    }

    let items: AgentTimelineItem[];
    try {
      items = await fetchTimeline(agentId);
    } catch {
      return state;
    }

    for (const item of items) {
      if (item.type !== "tool_call") continue;
      if (state.seenCallIds.has(item.callId)) continue;
      if (item.status === "failed" || item.status === "canceled") continue;
      state.seenCallIds.add(item.callId);

      const detail = item.detail;
      if (detail.type === "read") {
        const classified = classifyPosixPath(detail.filePath, pathCtx);
        if (classified.isSensitive) {
          this.markSecretTaint(agentId);
        }
      } else if (detail.type === "edit" || detail.type === "write") {
        this.recordFileModification(agentId, detail.filePath, pathCtx);
      } else if (detail.type === "fetch") {
        if (!isTrustedDomain(detail.url, this.trustedDomains)) {
          this.markUntrustedTaint(agentId);
        }
      } else if (detail.type === "search" && detail.toolName === "web_search") {
        this.markUntrustedTaint(agentId);
      } else if (detail.type === "shell") {
        if (SENSITIVE_SHELL_SECRET_REGEX.test(detail.command)) {
          this.markSecretTaint(agentId);
        }
      }
    }

    return state;
  }

  /**
   * Clear per-turn untrusted taint if desired on turn end while preserving
   * session-level secretTaint and modifiedEntrypoints.
   */
  onTurnEnd(agentId: string): void {
    const state = this.sessions.get(agentId);
    if (!state) return;
    if (state.untrustedTaint) {
      state.untrustedTaint = false;
      state.taintEpoch += 1;
    }
  }

  deleteSession(agentId: string): void {
    this.sessions.delete(agentId);
  }
}
