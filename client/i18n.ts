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
        teamPathHint:
          "Optional local file path distributed via Git, dotfiles, or MDM.",
        teamPathPlaceholder: "/path/to/team-policy.yaml",
      },
      act: {
        section: { title: "Automatic answering" },
        minSamples: "Minimum samples",
        minSamplesHint:
          "Reconciled shadow decisions required before act mode can answer (20-5000).",
        windowDays: "Sample window (days)",
        windowDaysHint:
          "Only decisions from this many recent days count (1-365).",
        autoFallback: "Fall back to shadow on false allow",
        autoFallbackHint:
          "Stop answering automatically if a past auto-allow turned out unsafe.",
        allowOverride: "Allow gate override",
        allowOverrideHint:
          "Lets you accept act mode before the sample requirement is met.",
        override: {
          accept: "Accept override",
          acceptHint:
            "Skip the sample-count requirement for the current plugin version.",
          revoke: "Revoke override",
          confirm:
            "This skips only the sample-count requirement. False allows still fall back to shadow while auto-fallback is on. The override expires when the plugin or its rules change.",
          confirmAction: "Accept",
          changed:
            "The plugin or its rules changed while confirming. Review the status and try again.",
          cancel: "Cancel",
          status: "Override",
          active: "Accepted",
          inactive: "Not accepted",
          expired: "Accepted, but expired",
        },
        status: {
          title: "Gate status",
          state: "State",
          reason: "Reason",
          samples: "Samples",
          lastReplay: "Last replay",
          never: "Never",
          fingerprint: "Fingerprint",
          falseAllows: "False allows",
          falseDenies: "False denies",
        },
        state: {
          replaying: "Replaying audit log",
          unavailable: "Unavailable",
          failed_false_allow: "Failed: false allow found",
          collecting: "Collecting",
          passed: "Passed",
          latched: "Active (latched)",
          suspended: "Suspended",
        },
        entries: {
          title: "Entries needing review",
          annotate: "Not a safety issue",
          acknowledge: "Acknowledge",
          kind: {
            false_allow: "False allow",
            orphan_deny: "Unmatched denial",
            corrupt_line: "Audit problem",
          },
        },
        help: {
          pwshUnavailable:
            "On hosts without PowerShell, human denials of PowerShell commands cannot be re-evaluated and keep the gate unavailable until acknowledged.",
        },
        validation: {
          range: "Enter a whole number within the allowed range (see hint).",
        },
        unconfirmed: "Unconfirmed automatic answers",
        integrity: "Audit integrity",
        integrityOk: "No integrity problems",
        integrityBad: "Problems found",
        replay: "Re-run replay",
        replayHint: "Re-evaluate the audit log against current rules.",
        replayAction: "Replay",
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
        includeRawHint:
          "原始 Provider 请求体在写入 JSONL 前会自动脱敏已知密钥。",
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
        teamPathHint:
          "可选的本地策略文件路径（可通过 Git、dotfiles 或 MDM 分发）。",
        teamPathPlaceholder: "/path/to/team-policy.yaml",
      },
      act: {
        section: { title: "自动应答" },
        minSamples: "最少样本数",
        minSamplesHint:
          "自动模式开始应答前所需的已对账影子决策数量（20-5000）。",
        windowDays: "样本窗口（天）",
        windowDaysHint: "仅统计最近这么多天内的决策（1-365）。",
        autoFallback: "出现误放行时回退到影子模式",
        autoFallbackHint: "如果过去的自动放行被证明不安全，则停止自动应答。",
        allowOverride: "允许手动放行门槛",
        allowOverrideHint: "允许在样本数未达标时手动接受自动模式。",
        override: {
          accept: "接受手动放行",
          acceptHint: "针对当前插件版本，跳过样本数量要求。",
          revoke: "撤销手动放行",
          confirm:
            "这只会跳过样本数量要求。开启自动回退时，出现误放行仍会回退到影子模式。插件或其规则发生变化后，此设置将失效。",
          confirmAction: "接受",
          changed: "确认期间插件或其规则发生了变化，请查看状态后重试。",
          cancel: "取消",
          status: "手动放行",
          active: "已接受",
          inactive: "未接受",
          expired: "已接受，但已失效",
        },
        status: {
          title: "门槛状态",
          state: "状态",
          reason: "原因",
          samples: "样本数",
          lastReplay: "上次重放",
          never: "从未",
          fingerprint: "指纹",
          falseAllows: "误放行数",
          falseDenies: "误拒绝数",
        },
        state: {
          replaying: "正在重放审计日志",
          unavailable: "不可用",
          failed_false_allow: "未通过：发现误放行",
          collecting: "收集中",
          passed: "已通过",
          latched: "已启用（已锁定）",
          suspended: "已暂停",
        },
        entries: {
          title: "待处理条目",
          annotate: "不是安全问题",
          acknowledge: "确认",
          kind: {
            false_allow: "误放行",
            orphan_deny: "未匹配的拒绝",
            corrupt_line: "审计问题",
          },
        },
        help: {
          pwshUnavailable:
            "在没有 PowerShell 的主机上，人工拒绝的 PowerShell 命令无法重新评估，在确认之前门槛会一直处于不可用状态。",
        },
        validation: { range: "请输入允许范围内的整数（见提示）。" },
        unconfirmed: "未确认的自动应答",
        integrity: "审计完整性",
        integrityOk: "没有完整性问题",
        integrityBad: "发现问题",
        replay: "重新运行重放",
        replayHint: "按当前规则重新评估审计日志。",
        replayAction: "重放",
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
