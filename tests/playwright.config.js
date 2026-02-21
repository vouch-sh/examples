const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./tests",
  /* Run tests sequentially — each example needs its own Docker container */
  workers: 1,
  /* 120s timeout per test — beforeAll hooks (Docker build + container start) need time */
  timeout: 120_000,
  /* Retry once on failure */
  retries: 1,
  /* Reporter */
  reporter: [["html", { open: "never" }], ["list"]],
  use: {
    /* Capture screenshot and video on failure */
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    trace: "retain-on-failure",
    /* No specific baseURL — tests manage their own containers */
  },
  projects: [
    {
      name: "chromium",
      use: {
        browserName: "chromium",
      },
    },
  ],
});
