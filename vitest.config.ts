// vitest.config.ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      exclude: [
        "node_modules/",
        "tests/",
        "**/*.test.ts",
        "**/*.spec.ts",
        "**/types.ts",
        "**/logger.ts",
      ],
    },
    // Increase timeout for cryptographic operations
    testTimeout: 10000,
  },
});
