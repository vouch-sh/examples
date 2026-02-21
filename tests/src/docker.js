const { execFileSync, spawn } = require("node:child_process");
const net = require("node:net");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "../..");

/**
 * Find an available port by briefly binding to port 0 and letting the OS assign one.
 *
 * @returns {Promise<number>}
 */
function getRandomPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
    server.on("error", reject);
  });
}

/**
 * Build a Docker image from a directory under the repo root.
 *
 * @param {string} dir - Relative path from repo root (e.g. "web/express-passport")
 * @param {string} imageName - Docker image tag name
 */
function build(dir, imageName) {
  const fullPath = path.join(REPO_ROOT, dir);
  execFileSync("docker", ["build", "-t", imageName, fullPath], {
    stdio: "pipe",
    timeout: 300_000, // 5 min build timeout
  });
}

/**
 * Run a Docker container in detached mode with the given env vars.
 * Uses standard port mapping (-p hostPort:3000) and adds
 * host.docker.internal so the container can reach the host.
 *
 * @param {{ name: string, image: string, port: number, env: Record<string, string> }} config
 * @returns {string} container name
 */
function run(config) {
  const port = config.port || 3000;
  const args = [
    "run", "-d",
    "--name", config.name,
    "-p", `${port}:3000`,
    "--add-host=host.docker.internal:host-gateway",
  ];

  for (const [k, v] of Object.entries(config.env)) {
    args.push("-e", `${k}=${v}`);
  }

  args.push(config.image);

  execFileSync("docker", args, { stdio: "pipe" });

  return config.name;
}

/**
 * Stop and remove a Docker container. Ignores errors if container doesn't exist.
 *
 * @param {string} name
 */
function stop(name) {
  try {
    execFileSync("docker", ["stop", name], {
      stdio: "pipe",
      timeout: 30_000,
    });
  } catch {
    // container may already be stopped
  }
  try {
    execFileSync("docker", ["rm", "-f", name], {
      stdio: "pipe",
      timeout: 15_000,
    });
  } catch {
    // container may already be removed
  }
}

/**
 * Get logs from a Docker container.
 *
 * @param {string} name
 * @returns {string}
 */
function logs(name) {
  try {
    return execFileSync("docker", ["logs", name], {
      stdio: "pipe",
      timeout: 10_000,
    }).toString();
  } catch {
    return "";
  }
}

/**
 * Poll until the container is responding to HTTP requests.
 *
 * @param {number} [port=3000]
 * @param {number} [timeoutMs=60000]
 */
async function waitForReady(port = 3000, timeoutMs = 120_000) {
  const start = Date.now();
  const url = `http://localhost:${port}`;

  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(2000),
        redirect: "manual",
      });
      // Any response (even a redirect) means the server is up
      if (res.status > 0) return;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }

  throw new Error(
    `Container did not become ready on port ${port} within ${timeoutMs}ms`,
  );
}

/**
 * Run a Docker container in attached mode (for native/CLI examples).
 * Returns a handle to read stdout and wait for exit.
 *
 * @param {{ name: string, image: string, env: Record<string, string> }} config
 */
function runAttached(config) {
  const args = ["run", "--name", config.name, "--add-host=host.docker.internal:host-gateway"];

  for (const [k, v] of Object.entries(config.env)) {
    args.push("-e", `${k}=${v}`);
  }

  args.push(config.image);

  let output = "";

  const proc = spawn("docker", args, {
    stdio: ["pipe", "pipe", "pipe"],
  });

  proc.stdout?.on("data", (data) => {
    output += data.toString();
  });
  proc.stderr?.on("data", (data) => {
    output += data.toString();
  });

  return {
    process: proc,
    stdout: () => output,
    waitForExit: (timeoutMs = 120_000) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          proc.kill();
          reject(
            new Error(
              `Container ${config.name} did not exit within ${timeoutMs}ms`,
            ),
          );
        }, timeoutMs);

        proc.on("close", (code) => {
          clearTimeout(timer);
          resolve(code ?? 1);
        });
      }),
    waitForOutput: (marker, timeoutMs = 60_000) =>
      new Promise((resolve, reject) => {
        const start = Date.now();
        const check = () => {
          if (output.includes(marker)) {
            resolve(output);
            return;
          }
          if (Date.now() - start > timeoutMs) {
            reject(
              new Error(
                `Marker "${marker}" not found in output within ${timeoutMs}ms. Output so far:\n${output}`,
              ),
            );
            return;
          }
          setTimeout(check, 500);
        };
        check();
      }),
  };
}

/**
 * Clean up any leftover test containers from previous runs.
 *
 * @param {string} [prefix="vouch-test-"]
 */
function cleanupStaleContainers(prefix = "vouch-test-") {
  try {
    const output = execFileSync(
      "docker",
      [
        "ps",
        "-a",
        "--filter",
        `name=${prefix}`,
        "--format",
        "{{.Names}}",
      ],
      { stdio: "pipe" },
    ).toString();

    const names = output.split("\n").filter(Boolean);
    for (const name of names) {
      stop(name);
    }
  } catch {
    // no containers to clean up
  }
}

module.exports = {
  getRandomPort,
  build,
  run,
  stop,
  logs,
  waitForReady,
  runAttached,
  cleanupStaleContainers,
};
