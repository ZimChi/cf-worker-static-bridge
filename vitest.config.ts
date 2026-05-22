import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
          AES_ENCRYPTION_KEY: "testonlytestonly",
          FRONTEND_BASE_URL: "http://localhost:3000",
          FORTE_LOCATION_ID: "test-location-id",
          FORTE_API_ACCESS_ID: "test-api-access-id",
          FORTE_SECURE_KEY: "test-secure-key",
          FORTE_MERCHANT_ID: "test-merchant-id",
          ENVIRONMENT: "development",
        },
      },
    }),
  ],
  test: {
    poolOptions: {
      workers: {
        singleWorker: true,
      },
    },
  },
});
