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
          "Act mode only answers low-risk (L0) prompts with a one-time allow, only for agy, and only while the evidence gate allows it. Everything else stays with you.",
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
          act: "Act (answer routine prompts once the evidence gate passes)",
        },
        effectiveValues: {
          shadow: "Shadow",
          off: "Off",
          act: "Act",
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
        autoFallbackOffWarning:
          "Auto-fallback is off: automatic answering continues even after a human denies a request the current rules would allow. Turn it back on unless you are reviewing every reported false allow.",
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
          openChat: "Open chat",
          gateHint: "The gate stays unavailable until each entry below is marked.",
          kind: {
            false_allow: "False allow",
            orphan_deny: "Unmatched denial",
            corrupt_line: "Audit problem",
            unevaluable_deny: "Denial could not be re-evaluated",
          },
          time: "Time",
          provider: "Provider",
          agent: "Agent",
          tool: "Tool",
          yourChoice: "Your choice",
          message: "Message",
          effects: "Effects",
          recovered: "Recovered from agent timeline",
          missing: "The plugin did not receive the request content at the time",
          choice: {
            allow: "Allow",
            allowOnce: "Allow once",
            allowAlways: "Always allow",
            deny: "Deny",
            denyOnce: "Deny once",
            denyAlways: "Always deny",
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
        integrityNormal: "Normal",
        integritySep: "; ",
        integrityUnavailable: "The gate is unavailable",
        integrityDetail: {
          orphan_deny: {
            one: "unmatched denial needs review",
            other: "unmatched denials need review",
          },
          unevaluable_deny: {
            one: "denial could not be re-evaluated",
            other: "denials could not be re-evaluated",
          },
          corrupt_line: {
            one: "audit problem needs review",
            other: "audit problems need review",
          },
        },
        counts: {
          orphan_deny: "Unmatched denials",
          unevaluable_deny: "Unevaluable denials",
          corrupt_line: "Corrupt audit lines",
        },
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
          "自动应答模式只会对低风险（L0）请求做一次性允许，仅适用于 agy，且仅在证据门槛允许时生效。其余请求都由你决定。",
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
          act: "自动应答模式（证据门槛通过后自动应答常规请求）",
        },
        effectiveValues: {
          shadow: "影子模式",
          off: "已关闭",
          act: "自动应答中",
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
        autoFallbackOffWarning:
          "自动回退已关闭：即使人工拒绝了当前规则会放行的请求，自动应答仍会继续。除非你会逐条审查报告的误放行，否则请重新开启。",
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
          openChat: "打开对话",
          gateHint: "在下列每个条目都被标记之前，门控将保持不可用。",
          kind: {
            false_allow: "误放行",
            orphan_deny: "未匹配的拒绝",
            corrupt_line: "审计问题",
            unevaluable_deny: "无法重新评估的拒绝",
          },
          time: "时间",
          provider: "提供方",
          agent: "智能体",
          tool: "工具",
          yourChoice: "你的选择",
          message: "留言",
          effects: "影响",
          recovered: "从智能体时间线恢复",
          missing: "插件当时未收到请求内容",
          choice: {
            allow: "允许",
            allowOnce: "允许一次",
            allowAlways: "始终允许",
            deny: "拒绝",
            denyOnce: "拒绝一次",
            denyAlways: "始终拒绝",
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
        integrityNormal: "正常",
        integritySep: "；",
        integrityUnavailable: "门控不可用",
        integrityDetail: {
          orphan_deny: {
            one: "条未匹配的拒绝待处理",
            other: "条未匹配的拒绝待处理",
          },
          unevaluable_deny: {
            one: "条拒绝无法重新评估",
            other: "条拒绝无法重新评估",
          },
          corrupt_line: {
            one: "个审计问题待处理",
            other: "个审计问题待处理",
          },
        },
        counts: {
          orphan_deny: "未匹配的拒绝数",
          unevaluable_deny: "无法评估的拒绝数",
          corrupt_line: "损坏的审计行数",
        },
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
