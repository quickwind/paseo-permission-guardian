Permission Guardian inspects agent permission requests in Paseo, normalizes tool calls across providers, and records shadow-mode audit logs so you can review how requests are classified before enabling automated decisions.

## How it works

When a coding agent requests permission to run a command, read or edit files, fetch a URL, or call an MCP tool, the plugin normalizes the provider payload into a common action model and reconciles the initial request with its final resolution.

Every request is written to rotated JSONL audit files under the plugin data directory with sensitive values redacted. In shadow mode, the plugin never answers prompts on your behalf and leaves all approvals to you.

## Setup and requirements

Requires Paseo daemon 0.16.0 or later. Works on macOS, Linux, and Windows.

No external accounts, API keys, or native binaries are required for the deterministic pipeline and shadow-mode auditing.

## Settings and behavior

- Mode: choose between `off`, `shadow` (default), and `act`. In the current release, shadow mode records and reconciles requests without automatically answering them.
- Treat deny as ask: converts any deny decision into a human prompt when automated actions are enabled.
- Timeline verbosity: controls whether notable events are appended to the agent timeline (`off`, `notable`, or `all`).
- Policy files: optional paths for user and team YAML policy files and pinned project policy hashes.

## Data and limits

Permission Guardian writes redacted audit records to local JSONL files on the daemon host and does not send data to external services by default. It is a prompt reducer, not a sandbox or security boundary; hard restrictions should remain in provider-native deny rules and OS isolation.
