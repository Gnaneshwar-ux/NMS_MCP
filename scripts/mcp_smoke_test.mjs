#!/usr/bin/env node

import { spawn } from "node:child_process";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";

function encodeMessage(message) {
  return `${JSON.stringify(message)}\n`;
}

function quoteShell(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function lastNonEmptyLine(value) {
  return String(value ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .at(-1) ?? "";
}

class McpStdioClient {
  constructor(command, args, options = {}) {
    this.command = command;
    this.args = args;
    this.options = options;
    this.nextId = 1;
    this.buffer = Buffer.alloc(0);
    this.pending = new Map();
    this.notifications = [];
  }

  start() {
    this.child = spawn(this.command, this.args, {
      cwd: this.options.cwd,
      env: { ...process.env, ...(this.options.env ?? {}) },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });

    this.child.stdout.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)]);
      this.#drain();
    });

    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk) => {
      this.notifications.push({
        channel: "stderr",
        text: String(chunk),
      });
    });

    this.child.on("close", (code, signal) => {
      const error = new Error(
        `MCP server exited unexpectedly (code=${code ?? "null"}, signal=${signal ?? "none"}).`,
      );

      for (const pending of this.pending.values()) {
        pending.reject(error);
      }

      this.pending.clear();
    });
  }

  async initialize() {
    const result = await this.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: {
        name: "mcp-smoke-test",
        version: "1.0.0",
      },
    });

    this.notify("notifications/initialized", {});
    return result;
  }

  request(method, params = {}) {
    const id = this.nextId++;
    const payload = {
      jsonrpc: "2.0",
      id,
      method,
      params,
    };

    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.child.stdin.write(encodeMessage(payload));
    });
  }

  notify(method, params = {}) {
    this.child.stdin.write(
      encodeMessage({
        jsonrpc: "2.0",
        method,
        params,
      }),
    );
  }

  async callTool(name, args = {}) {
    const response = await this.request("tools/call", {
      name,
      arguments: args,
    });

    if (response.error) {
      throw new Error(
        `Tool call failed at MCP layer for ${name}: ${JSON.stringify(response.error)}`,
      );
    }

    const result = response.result ?? {};
    if (result.structuredContent) {
      return result.structuredContent;
    }

    const text = result.content?.[0]?.text;
    return typeof text === "string" ? JSON.parse(text) : result;
  }

  async close() {
    if (!this.child) {
      return;
    }

    try {
      this.child.stdin.end();
    } catch {
      // Ignore broken pipe on shutdown.
    }

    if (!this.child.killed) {
      this.child.kill("SIGTERM");
    }

    await delay(250);

    if (!this.child.killed) {
      this.child.kill("SIGKILL");
    }
  }

  #drain() {
    while (true) {
      const newlineIndex = this.buffer.indexOf("\n");
      if (newlineIndex === -1) {
        return;
      }

      const line = this.buffer.slice(0, newlineIndex).toString("utf8").replace(/\r$/, "");
      this.buffer = this.buffer.slice(newlineIndex + 1);
      const message = JSON.parse(line);

      if (Object.prototype.hasOwnProperty.call(message, "id")) {
        const pending = this.pending.get(message.id);
        if (!pending) {
          continue;
        }

        this.pending.delete(message.id);
        pending.resolve(message);
        continue;
      }

      this.notifications.push(message);
    }
  }
}

async function main() {
  const host = process.env.SSH_TEST_HOST;
  const port = Number.parseInt(process.env.SSH_TEST_PORT ?? "22", 10);
  const username = process.env.SSH_TEST_USER;
  const password = process.env.SSH_TEST_PASSWORD;
  const dbUsername = process.env.DB_TEST_USER;
  const dbPassword = process.env.DB_TEST_PASSWORD;
  const dbConnectString = process.env.DB_TEST_CONNECT_STRING;
  const dbHost = process.env.DB_TEST_HOST;
  const dbPort = Number.parseInt(process.env.DB_TEST_PORT ?? "1521", 10);
  const dbServiceName = process.env.DB_TEST_SERVICE_NAME;
  const dbSid = process.env.DB_TEST_SID;

  if (!host || !username || !password) {
    throw new Error(
      "Set SSH_TEST_HOST, SSH_TEST_PORT, SSH_TEST_USER, and SSH_TEST_PASSWORD before running the smoke test.",
    );
  }

  const client = new McpStdioClient(process.execPath, ["dist/index.js"], {
    cwd: process.cwd(),
  });

  const summary = {
    initialized: null,
    tools: [],
    policy: null,
    commandReviews: [],
    sqlReviews: [],
    dbSession: null,
    session: null,
    sessionsBeforeClose: null,
    commands: [],
    longRunning: null,
    closeSession: null,
    serverDiagnostics: client.notifications,
  };

  let sessionId;
  let dbSessionId;

  const runCommand = async (label, command, options = {}) => {
    const request = {
      sessionId,
      command,
      ...options,
    };

    delete request.autoConfirm;
    const shouldAutoConfirm = options.autoConfirm ?? true;

    let result = await client.callTool("execute_command", request);

    if (
      shouldAutoConfirm &&
      result.error === "CONFIRMATION_REQUIRED" &&
      result.approvalId &&
      result.requiredConfirmationToken
    ) {
      result = await client.callTool("execute_command", {
        ...request,
        approvalId: result.approvalId,
        userConfirmation: result.requiredConfirmationToken,
      });
    }

    summary.commands.push({
      label,
      command,
      result,
    });

    return result;
  };

  const runSql = async (label, sql, options = {}) => {
    if (!dbSessionId) {
      throw new Error("DB session is not available.");
    }

    const request = {
      dbSessionId,
      sql,
      ...options,
    };

    delete request.autoConfirm;
    const shouldAutoConfirm = options.autoConfirm ?? true;

    let result = await client.callTool("execute_sql", request);

    if (
      shouldAutoConfirm &&
      result.error === "CONFIRMATION_REQUIRED" &&
      result.approvalId &&
      result.requiredConfirmationToken
    ) {
      result = await client.callTool("execute_sql", {
        ...request,
        approvalId: result.approvalId,
        userConfirmation: result.requiredConfirmationToken,
      });
    }

    summary.sqlReviews.push({
      label,
      sql,
      result,
    });

    return result;
  };

  try {
    client.start();
    summary.initialized = (await client.initialize()).result;
    summary.tools = (await client.request("tools/list", {})).result?.tools ?? [];
    summary.policy = await client.callTool("read_policy", {});
    summary.sqlReviews.push({
      label: "review-select",
      sql: "select count(*) as class_count from classes",
      result: await client.callTool("review_sql", {
        sql: "select count(*) as class_count from classes",
      }),
    });
    summary.sqlReviews.push({
      label: "review-alter-session",
      sql: "alter session set current_schema = NMS",
      result: await client.callTool("review_sql", {
        sql: "alter session set current_schema = NMS",
      }),
    });
    summary.sqlReviews.push({
      label: "review-delete-blocked",
      sql: "delete from classes where 1 = 2",
      result: await client.callTool("review_sql", {
        sql: "delete from classes where 1 = 2",
      }),
    });

    const connectResult = await client.callTool("ssh_connect", {
      host,
      port,
      username,
      authMethod: "password",
      password,
      sessionLabel: "nms-smoke-test",
      connectTimeout: 20000,
    });

    summary.session = connectResult;
    if (connectResult.error) {
      throw new Error(JSON.stringify(connectResult));
    }

    sessionId = connectResult.sessionId;

    summary.commandReviews.push({
      label: "review-ps",
      command: "ps -ef | grep -i nms_1 | grep -v grep",
      result: await client.callTool("review_command", {
        sessionId,
        command: "ps -ef | grep -i nms_1 | grep -v grep",
      }),
    });
    summary.commandReviews.push({
      label: "review-smsReport",
      command: "smsReport 2>&1 | head -n 40",
      result: await client.callTool("review_command", {
        sessionId,
        command: "smsReport 2>&1 | head -n 40",
      }),
    });
    summary.commandReviews.push({
      label: "review-rm",
      command: "rm -f /tmp/mcp_probe",
      result: await client.callTool("review_command", {
        sessionId,
        command: "rm -f /tmp/mcp_probe",
      }),
    });

    await runCommand("whoami", "whoami");
    await runCommand("pwd", "pwd");
    await runCommand("hostname", "hostname");
    await runCommand("date", "date");
    await runCommand("source-nmsrc", "source ~/.nmsrc", {
      autoConfirm: true,
    });
    await runCommand(
      "nms-tools-on-path",
      "printf 'smsReport=%s\\nISQL=%s\\n' \"$(command -v smsReport || echo missing)\" \"$(command -v ISQL || echo missing)\"",
    );
    await runCommand("smsReport", "smsReport 2>&1 | head -n 40", {
      timeout: 60000,
    });
    await runCommand(
      "process-check",
      "ps -ef | grep -i nms_1 | grep -v grep | head -n 10",
    );

    const logDirResult = await runCommand(
      "find-log-dir",
      "find /appl/weblogic/user_projects/domains -path '*/servers/nms_1/logs' -type d 2>/dev/null | head -n 1",
      { timeout: 60000 },
    );
    let logDir = lastNonEmptyLine(logDirResult.stdout);

    if (!logDir) {
      const fallbackLogDirResult = await runCommand(
        "find-log-dir-fallback",
        "find /home/nmsadmin -path '*/servers/nms_1/logs' -type d 2>/dev/null | head -n 1",
        { timeout: 60000 },
      );
      logDir = lastNonEmptyLine(fallbackLogDirResult.stdout);
    }

    if (logDir) {
      const logFileResult = await runCommand(
        "choose-log-file",
        `for f in ${quoteShell(`${logDir}/nms_1.log`)} ${quoteShell(`${logDir}/nms_1.out`)}; do [ -f "$f" ] && echo "$f" && break; done`,
      );
      const logFile = lastNonEmptyLine(logFileResult.stdout);

      if (logFile) {
        await runCommand("tail-log", `tail -n 20 ${quoteShell(logFile)}`, {
          timeout: 60000,
        });
        await runCommand(
          "grep-log-errors",
          `grep -i -n -E 'ORA-28001|DeploymentAssertionError|ERROR|Exception' ${quoteShell(logFile)} | tail -n 20`,
          { timeout: 60000 },
        );
        await runCommand(
          "locate-log",
          "command -v locate >/dev/null 2>&1 && locate -i nms_1.log | head -n 5 || echo 'locate not available'",
          { timeout: 60000 },
        );

        const followCommand = await client.callTool("execute_command", {
          sessionId,
          command: `tail -n 5 -f ${quoteShell(logFile)}`,
          timeout: 1500,
        });
        const duringFollow = await client.callTool("read_output", {
          sessionId,
          clear: true,
        });
        const interruptResult = await client.callTool("interrupt_session", {
          sessionId,
          signal: "ctrlC",
          waitForReadyMs: 5000,
          clearBuffer: false,
        });
        const afterInterrupt = await client.callTool("read_output", {
          sessionId,
          clear: true,
        });

        let recovery;
        for (let attempt = 0; attempt < 10; attempt += 1) {
          recovery = await client.callTool("execute_command", {
            sessionId,
            command: "pwd",
            timeout: 10000,
          });

          if (recovery.error !== "SHELL_BUSY") {
            break;
          }

          await delay(500);
        }

        summary.longRunning = {
          command: `tail -n 5 -f ${logFile}`,
          followCommand,
          duringFollow,
          interruptResult,
          afterInterrupt,
          recoveryCommand: "pwd",
          recovery,
        };
      }
    }

    await runCommand(
      "product-bin-check",
      "find /home/nmsadmin/nms/product -maxdepth 4 -type f \\( -name 'smsReport' -o -name 'ISQL' \\) 2>/dev/null | head -n 20",
      { timeout: 60000 },
    );

    if (
      dbUsername &&
      dbPassword &&
      (dbConnectString || (dbHost && (dbServiceName || dbSid)))
    ) {
      const dbConnectResult = await client.callTool("oracle_connect", {
        username: dbUsername,
        password: dbPassword,
        ...(dbConnectString
          ? { connectString: dbConnectString }
          : {
              host: dbHost,
              port: dbPort,
              ...(dbServiceName ? { serviceName: dbServiceName } : { sid: dbSid }),
            }),
        sessionLabel: "oracle-db-smoke-test",
        connectTimeout: 20000,
      });

      summary.dbSession = {
        connect: dbConnectResult,
      };

      if (!dbConnectResult.error) {
        dbSessionId = dbConnectResult.dbSessionId;
        summary.dbSession.query = await runSql(
          "db-read-only-query",
          "select sysdate as current_time from dual",
          {
            maxRows: 5,
            timeout: 20000,
          },
        );
        summary.dbSession.blockedSql = await client.callTool("execute_sql", {
          dbSessionId,
          sql: "delete from dual where 1 = 2",
        });
        summary.dbSession.sessions = await client.callTool("list_db_sessions", {});
        summary.dbSession.close = await client.callTool("close_db_session", {
          dbSessionId,
        });
        dbSessionId = undefined;
      }
    }

    summary.sessionsBeforeClose = await client.callTool("list_sessions", {});

    summary.closeSession = await client.callTool("close_session", { sessionId });
  } finally {
    if (dbSessionId) {
      try {
        await client.callTool("close_db_session", { dbSessionId });
      } catch {
        // Best-effort cleanup for optional DB smoke runs.
      }
    }
    await client.close();
  }

  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

main().catch((error) => {
  console.error(error.stack ?? String(error));
  process.exit(1);
});
