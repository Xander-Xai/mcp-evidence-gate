import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Only collect the main repository's direct test files. Companion worktrees
    // may live below the checkout, but their suites have their own CI.
    include: ["tests/*.test.ts"]
  }
});
