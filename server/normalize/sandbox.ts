const SANDBOX_BYPASS_KEY = /^(bypass_?sandbox|dangerously.*|unsandboxed)$/i;

function isTruthyFlag(value: unknown): boolean {
  if (value === true) return true;
  if (typeof value === "string") return value.trim().toLowerCase() === "true";
  if (typeof value === "number") return Number.isFinite(value) && value !== 0;
  return false;
}

export function hasSandboxBypassFlag(input: Record<string, unknown> | undefined): boolean {
  if (!input) return false;
  return Object.entries(input).some(([k, v]) => SANDBOX_BYPASS_KEY.test(k) && isTruthyFlag(v));
}
