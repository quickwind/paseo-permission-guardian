Permission Guardian inspects agent permission requests in Paseo, normalizes tool calls across providers, and records shadow-mode audit logs so you can review how requests are classified before enabling automated decisions.

## How it works

When a coding agent requests permission to run a command, read or edit files, fetch a URL, or call an MCP tool, the plugin normalizes the provider payload into a common action model and reconciles the initial request with its final resolution.

Every request is written to rotated JSONL audit files under the plugin data directory with sensitive values redacted. In shadow mode, the plugin never answers prompts on your behalf and leaves all approvals to you.

## Setup and requirements

Requires Paseo daemon 0.16.0 or later. Works on macOS, Linux, and Windows.

No external accounts, API keys, or native binaries are required for the deterministic pipeline and shadow-mode auditing.

## Settings and behavior

- Mode: choose between `off`, `shadow` (default), and `act`. Shadow mode records and reconciles requests without answering them. Act mode answers routine prompts, but only while the evidence gate allows it; otherwise the plugin stays in shadow mode.
- Treat deny as ask: converts any deny decision into a human prompt when automated actions are enabled.
- Timeline verbosity: controls whether notable events are appended to the agent timeline (`off`, `notable`, or `all`).
- Evidence gate: act mode becomes effective only after the plugin has replayed your own recorded history with the current rules and found enough human-handled requests (200 within 30 days by default, both adjustable) with no disagreement, meaning no case where the plugin would allow a request that you denied. A fresh install stays in shadow mode. After a disagreement the plugin returns to shadow mode until you mark the denial as not a safety issue. Changing the plugin version, policy or relevant settings requires the gate to pass again.
- Override: you can accept the risk to skip the sample count. It applies only to the current rules, is recorded in the audit log, and never applies while the gate is replaying or unavailable.
- Automatic answering: in act mode, low-risk requests are answered with a one-time allow. High-risk requests that the rules deny can be answered with a one-time deny only when treat-deny-as-ask is off and no human has allowed a similar request. Everything else stays with you. In this version only the agy provider is answered automatically.
- Policy files: optional paths for user and team YAML policy files and pinned project policy hashes.

## Data and limits

Permission Guardian writes redacted audit records to local JSONL files on the daemon host and does not send data to external services by default. It is a prompt reducer, not a sandbox or security boundary. In act mode, editing ordinary project code and then running a project command is treated as low risk; hard restrictions should remain in provider-native deny rules and OS isolation.
