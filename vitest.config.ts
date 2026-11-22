import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Live PowerShell hosts cold-start slowly on shared CI runners (observed >5 s on ubuntu-latest).
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
