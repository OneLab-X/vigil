import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
    env: {
      VIGIL_DATABASE_URL: "postgres://vigil_app:vigil_app_dev@127.0.0.1:54329/vigil_test",
      VIGIL_OWNER_DATABASE_URL: "postgres://vigil_owner:vigil_owner_dev@127.0.0.1:54329/vigil_test",
      VIGIL_AGENTS_URL: "http://127.0.0.1:18091",
      VIGIL_DATA_DIR: "/tmp/vigil-test-data",
      VIGIL_RUN_WORKER: "0",
    },
  },
});
