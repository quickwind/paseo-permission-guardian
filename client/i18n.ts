import { defineTranslations } from "@getpaseo/plugin/client";

export const messages = defineTranslations({
  resources: {
    en: {
      settings: {
        title: "Permission Guardian",
        resetLabel: "Reset settings",
        resetHint: "Restore default Permission Guardian settings.",
        resetAction: "Reset",
        p0Notice:
          "P0 runs in shadow-only mode. Deterministic AST rules and act mode arrive in P1a/P2.",
        loadStatusError: "Failed to load status",
      },
      sections: {
        runtimeMode: "Runtime mode",
        auditAndPolicy: "Audit & policy",
        shadowAuditStatus: "Shadow audit status",
      },
      mode: {
        label: "Guardian mode",
        hint: "Shadow mode records and reconciles every permission request without answering prompts.",
        options: {
          shadow: "Shadow (observe & audit only)",
          off: "Off (disabled)",
          act: "Act (available in P2, currently shadow)",
        },
        effectiveValues: {
          shadow: "Shadow",
          off: "Off",
        },
      },
      denyAsAsk: {
        label: "Treat deny as ask",
        hint: "Convert deny verdicts into human prompts instead of automatically denying.",
      },
      timeline: {
        label: "Timeline verbosity",
        hint: "Controls which events are appended to agent timelines.",
        options: {
          notable: "Notable events only",
          all: "All events",
          off: "Off",
        },
      },
      audit: {
        includeRawLabel: "Include raw payloads in audit log",
        includeRawHint:
          "Raw provider payloads are redacted for known secrets before writing to JSONL.",
      },
      windowsShell: {
        label: "Default Windows shell",
        hint: "Used when a Windows exec request does not specify a shell.",
        options: {
          pwsh7: "PowerShell 7 (pwsh)",
          pwsh5: "Windows PowerShell 5.1",
          cmd: "Command Prompt (cmd.exe)",
        },
      },
      policy: {
        userPathLabel: "User policy path",
        userPathHint: "Local YAML policy file path (read-only from UI).",
        teamPathLabel: "Team policy path",
        teamPathHint: "Optional local file path distributed via Git, dotfiles, or MDM.",
        teamPathPlaceholder: "/path/to/team-policy.yaml",
      },
      status: {
        errorLabel: "Status error",
        effectiveModeLabel: "Effective mode",
        totalRequestsLabel: "Total requests",
        reconciledPendingLabel: "Reconciled / Pending",
        falseAllowsLabel: "False allows",
        auditDirLabel: "Audit directory",
        loading: "Loading...",
        refreshLabel: "Refresh metrics",
        refreshAction: "Refresh",
      },
    },
    zh: {
      settings: {
        title: "权限守卫",
        resetLabel: "重置设置",
        resetHint: "恢复权限守卫的默认配置。",
        resetAction: "重置",
        p0Notice:
          "P0 阶段仅以影子模式运行，确定性 AST 规则与自动响应模式将在 P1a/P2 阶段提供。",
        loadStatusError: "加载状态失败",
      },
      sections: {
        runtimeMode: "运行模式",
        auditAndPolicy: "审计与策略",
        shadowAuditStatus: "影子审计状态",
      },
      mode: {
        label: "守卫模式",
        hint: "影子模式仅记录并对账每一次权限请求，不会自动替你做出审批决定。",
        options: {
          shadow: "影子模式（仅观察与审计）",
          off: "关闭（已停用）",
          act: "自动模式（P2 提供，当前按影子模式运行）",
        },
        effectiveValues: {
          shadow: "影子模式",
          off: "已关闭",
        },
      },
      denyAsAsk: {
        label: "将拒绝转为人工询问",
        hint: "将拒绝判定转为人工确认提示，而不是直接自动拒绝。",
      },
      timeline: {
        label: "时间线输出级别",
        hint: "控制哪些事件会被追加到 Agent 时间线中。",
        options: {
          notable: "仅重要事件",
          all: "全部事件",
          off: "关闭",
        },
      },
      audit: {
        includeRawLabel: "审计日志包含原始请求体",
        includeRawHint: "原始 Provider 请求体在写入 JSONL 前会自动脱敏已知密钥。",
      },
      windowsShell: {
        label: "Windows 默认 Shell",
        hint: "当 Windows 执行请求未显式指定 Shell 时使用。",
        options: {
          pwsh7: "PowerShell 7 (pwsh)",
          pwsh5: "Windows PowerShell 5.1",
          cmd: "命令提示符 (cmd.exe)",
        },
      },
      policy: {
        userPathLabel: "用户策略路径",
        userPathHint: "本地 YAML 策略文件路径（界面仅只读加载，不回写文件）。",
        teamPathLabel: "团队策略路径",
        teamPathHint: "可选的本地策略文件路径（可通过 Git、dotfiles 或 MDM 分发）。",
        teamPathPlaceholder: "/path/to/team-policy.yaml",
      },
      status: {
        errorLabel: "状态错误",
        effectiveModeLabel: "当前生效模式",
        totalRequestsLabel: "总请求数",
        reconciledPendingLabel: "已对账 / 待处理",
        falseAllowsLabel: "误放行数 (False allows)",
        auditDirLabel: "审计日志目录",
        loading: "加载中...",
        refreshLabel: "刷新统计",
        refreshAction: "刷新",
      },
    },
  },
});
