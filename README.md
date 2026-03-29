# SSH + Oracle DB MCP Server

Production-grade MCP server for persistent SSH PTY sessions and cached Oracle DB diagnostic sessions, with strict server-side review, confirmation, and audit logging.

## Highlights

- Uses `ssh2` directly so the server can keep a real PTY shell alive across MCP calls
- Keeps Oracle DB connections open across MCP calls so agents can reuse DB session state
- Supports guided interactive PTY commands with prompt classification and follow-up input tools
- Auto-runs only an explicit safe read-only command list and safe SELECT queries
- Requires user confirmation for anything outside the explicit safe list
- Supports custom project and NMS commands, but never runs them blindly when MCP is not confident about the consequences
- Writes an audit record for SSH commands, Oracle SQL, hosts, DB targets, approvals, blocks, starts, completions, timeouts, and interrupts to a file on disk
- Supports MCP stdio by default and optional HTTP + SSE transport

## Project layout

```text
src/
|-- index.ts
|-- session.ts
|-- ssh.ts
|-- executor.ts
|-- sudo.ts
|-- db.ts
|-- db-session.ts
|-- policy.ts
|-- sql-policy.ts
|-- policy-config.ts
|-- oracledb.d.ts
`-- utils.ts

ssh-mcp-policy.json
ssh-mcp-policy.example.json
mcp-audit.ndjson
scripts/mcp_smoke_test.mjs
```

## Environment variables

Shell and transport:

- `MCP_SSH_IDLE_TIMEOUT_MS` default `1800000`
- `MCP_SSH_DEFAULT_TIMEOUT_MS` default `30000`
- `MCP_SSH_APPROVAL_TTL_MS` default `600000`
- `MCP_SSH_MAX_SESSIONS` default `10`
- `MCP_SSH_POLICY_FILE` optional path to a custom JSON policy file
- `MCP_TRANSPORT` `stdio` or `sse`, default `stdio`
- `MCP_SSE_PORT` default `3000`

Oracle DB:

- `MCP_DB_IDLE_TIMEOUT_MS` default `1800000`
- `MCP_DB_DEFAULT_TIMEOUT_MS` default `30000`
- `MCP_DB_MAX_SESSIONS` default `5`
- `MCP_DB_MAX_ROWS` default `200`
- `MCP_DB_CONFIG_DIR` optional Oracle Net config directory for wallet or TNS-based connections
- `MCP_DB_WALLET_LOCATION` optional wallet directory
- `MCP_DB_WALLET_PASSWORD` optional wallet password
- `MCP_DB_HTTPS_PROXY` optional HTTPS proxy for secure Oracle DB connections
- `MCP_DB_HTTPS_PROXY_PORT` optional proxy port

Audit:

- `MCP_AUDIT_LOG_FILE` default `C:\ProjectNMS\NMS_MCP\mcp-audit.ndjson` when running from this repo

## Tools

Shell tools:

- `ssh_connect`
- `review_command`
- `execute_command`
- `start_interactive_command`
- `write_stdin`
- `send_interaction_input`
- `read_output`
- `read_interaction_state`
- `resize_terminal`
- `list_sessions`
- `close_session`
- `interrupt_session`

Oracle DB tools:

- `oracle_connect`
- `review_sql`
- `execute_sql`
- `list_db_sessions`
- `close_db_session`
- `interrupt_db_session`

Shared visibility:

- `read_policy`
- `read_audit_log`

## Safety model

The server does not trust user intent or agent intent. It reviews the exact command or SQL text first, decides whether it is on the explicit safe list, and otherwise requires confirmation before running it.

## Interactive PTY model

For simple commands, use `execute_command`.

For anything that may prompt, stream, or open a REPL, use the guided interactive flow:

1. `start_interactive_command`
2. `read_interaction_state`
3. `send_interaction_input`
4. `interrupt_session` or wait for the command to complete

The server keeps the PTY stateful, classifies common prompt types, and returns structured interaction metadata such as:

- `promptType`
- `promptText`
- `expectsInput`
- `safeToAutoRespond`
- `suggestedInputs`
- `foregroundCommand`

Prompt types currently include shell prompts, sudo/password prompts, yes/no prompts, press-enter prompts, Python REPL prompts, SQL prompts, pagers, and fallback unknown interactive prompts.

### Safe shell auto-run list

These commands can auto-run when MCP can clearly recognize them and does not detect extra unsafe behavior:

- `ls`
- `pwd`
- `cd`
- `grep`
- `find`
- `locate`
- `cat`
- `ps`
- `tail`
- `ISQL` read-only `SELECT` commands only
- `ISQL -admin` read-only `SELECT` commands only

Notes:

- `cd` is treated as low-impact and allowed because it only changes the active shell directory
- Commands that start interactive terminal programs such as `python`, `sqlplus`, `ISQL`, `tail -f`, `less`, `top`, or `ssh` are not treated as safe auto-run commands
- If MCP sees shell redirection to files, inline scripts, `sudo`, or other risky patterns, it will stop auto-running and ask first
- If MCP is not confident that a custom project command is harmless, it asks first

### Safe SQL auto-run list

These statements can auto-run when MCP can clearly recognize them as read-only:

- `SELECT ...`
- `WITH ... SELECT ...`

Notes:

- Package or schema-qualified function calls inside a `SELECT` are not auto-run if MCP is not confident about side effects
- `SELECT ... FOR UPDATE` is not auto-run

### Confirmation behavior

Anything outside the safe auto-run lists requires explicit user confirmation.

What MCP returns:

- `decision: "allow"` for explicit safe commands or queries
- `decision: "approval_required"` for unknown, custom, mutating, or higher-risk actions
- `decision: "blocked"` only when a deny rule or explicit blocked category in your policy file says MCP must refuse it entirely

Confirmation rule:

- MCP asks the agent to show the exact command or SQL and a simple consequence summary
- The user must reply with exact `CONFIRM`
- The agent must retry with the returned `approvalId` and `userConfirmation: "CONFIRM"`
- MCP should never self-confirm

### Audit logging

Every reviewed or executed operation is appended to the audit file:

- SSH host and username
- DB target and username
- command or SQL text
- review / block / start / completion / timeout / interrupt events
- timestamps and structured details

The default audit file is `mcp-audit.ndjson`. Each line is one JSON object so it is easy to search or archive.

## Policy files

The server loads [ssh-mcp-policy.json](./ssh-mcp-policy.json) by default. You can point to a different file with `MCP_SSH_POLICY_FILE`.

Current policy file model:

- Top-level fields apply to shell command policy
- Nested `sqlPolicy` fields apply to Oracle SQL policy
- `denyRules` always win over `allowRules`
- `blockedCategories` are for commands or SQL you want MCP to hard-refuse
- `allowRules` are for narrow exceptions you want MCP to recognize explicitly

Default files:

- [ssh-mcp-policy.json](./ssh-mcp-policy.json) keeps hard blocks empty by default and relies on the safe auto-run list plus confirmation flow
- [ssh-mcp-policy.example.json](./ssh-mcp-policy.example.json) shows how to deny dangerous patterns and allow very narrow exceptions

### Policy file shape

```json
{
  "blockedCategories": [],
  "approvalCategories": ["session-state"],
  "allowRules": [],
  "denyRules": [
    {
      "name": "block-service-restarts",
      "regex": "\\b(systemctl|service)\\b.*\\b(start|stop|restart|reload)\\b",
      "reason": "Hard-block service interruption through MCP."
    }
  ],
  "sqlPolicy": {
    "blockedCategories": [],
    "approvalCategories": ["session-state"],
    "allowRules": [],
    "denyRules": [
      {
        "name": "block-delete",
        "regex": "^delete\\b",
        "reason": "Hard-block row deletion through MCP."
      }
    ]
  }
}
```

## Recommended agent behavior

Use these tools anytime they would help NMS development, debugging, runtime validation, issue analysis, or environment checks.

Good uses:

- SSH tools for host state, WebLogic status, log reading, process inspection, `.nmsrc` setup, and NMS utility checks
- Oracle DB tools for safe read-only queries, counts, data checks, schema context checks, and troubleshooting evidence
- `review_command` for custom project commands when MCP is not fully certain
- `review_sql` for any SQL beyond a plain safe `SELECT`

Required behavior:

1. Show the exact command or SQL to the user before asking for confirmation.
2. Include the simple consequence summary from MCP in that prompt.
3. Never self-supply `CONFIRM`.
4. Treat `POLICY_BLOCKED` as final unless a human intentionally changes the policy file.
5. Check the audit log when you need proof of what MCP reviewed or executed.

## Run

On Windows PowerShell, use `npm.cmd` and `codex.cmd`. The `.ps1` shims may be blocked by execution policy on locked-down machines.

Install dependencies:

```powershell
npm.cmd install
```

Build:

```powershell
npm.cmd run build
```

Start over stdio:

```powershell
npm.cmd start
```

Start over SSE:

```powershell
$env:MCP_TRANSPORT = "sse"
$env:MCP_SSE_PORT = "3000"
npm.cmd start
```

## Codex setup

Build the project first:

```powershell
cd C:\ProjectNMS\NMS_MCP
npm.cmd install
npm.cmd run build
```

Register the server with Codex:

```powershell
codex.cmd mcp add nms-mcp `
  --env MCP_SSH_DEFAULT_TIMEOUT_MS=120000 `
  --env MCP_SSH_IDLE_TIMEOUT_MS=3600000 `
  --env MCP_SSH_APPROVAL_TTL_MS=600000 `
  --env MCP_SSH_POLICY_FILE=C:\ProjectNMS\NMS_MCP\ssh-mcp-policy.json `
  --env MCP_SSH_MAX_SESSIONS=10 `
  --env MCP_DB_DEFAULT_TIMEOUT_MS=60000 `
  --env MCP_DB_IDLE_TIMEOUT_MS=3600000 `
  --env MCP_DB_MAX_SESSIONS=5 `
  --env MCP_DB_MAX_ROWS=200 `
  --env MCP_AUDIT_LOG_FILE=C:\ProjectNMS\NMS_MCP\mcp-audit.ndjson `
  -- node C:\ProjectNMS\NMS_MCP\dist\index.js
```

Verify it is registered:

```powershell
codex.cmd mcp list
```

Notes:

- Replace `C:\ProjectNMS\NMS_MCP` with your actual checkout path if it is different
- Do not store SSH passwords or DB passwords in the Codex MCP registration; pass them when calling `ssh_connect` or `oracle_connect`
- Tell Codex to review first, show the exact command or SQL to the user, and only continue after exact `CONFIRM`

## Cline setup

Build the project first if you have not already:

```powershell
cd C:\ProjectNMS\NMS_MCP
npm.cmd install
npm.cmd run build
```

Open Cline and add a local stdio MCP server using this shape:

```json
{
  "mcpServers": {
    "nms-mcp": {
      "command": "node",
      "args": ["C:\\ProjectNMS\\NMS_MCP\\dist\\index.js"],
      "env": {
        "MCP_SSH_DEFAULT_TIMEOUT_MS": "120000",
        "MCP_SSH_IDLE_TIMEOUT_MS": "3600000",
        "MCP_SSH_APPROVAL_TTL_MS": "600000",
        "MCP_SSH_POLICY_FILE": "C:\\ProjectNMS\\NMS_MCP\\ssh-mcp-policy.json",
        "MCP_SSH_MAX_SESSIONS": "10",
        "MCP_DB_DEFAULT_TIMEOUT_MS": "60000",
        "MCP_DB_IDLE_TIMEOUT_MS": "3600000",
        "MCP_DB_MAX_SESSIONS": "5",
        "MCP_DB_MAX_ROWS": "200",
        "MCP_AUDIT_LOG_FILE": "C:\\ProjectNMS\\NMS_MCP\\mcp-audit.ndjson"
      },
      "disabled": false
    }
  }
}
```

Notes:

- Do not store SSH passwords or DB passwords in the Cline config; pass them when calling `ssh_connect` or `oracle_connect`
- Ask Cline to never self-confirm and to show the exact command or SQL plus the consequence summary in the chat before proceeding

## First use

SSH:

1. Call `ssh_connect`.
2. Call `review_command` for anything outside the obvious safe list or when you want MCP to explain the risk before asking the user.
3. Use `execute_command` for one-shot commands, or `start_interactive_command` for prompt-driven commands.
4. If MCP returns `CONFIRMATION_REQUIRED`, show the exact command and the summary, then retry with the same `approvalId` and `userConfirmation: "CONFIRM"`.
5. For interactive runs, inspect `read_interaction_state` and continue with `send_interaction_input`.

Oracle DB:

1. Call `oracle_connect` with DB credentials and either `connectString` or `host` plus `serviceName` or `sid`.
2. Call `review_sql` for anything beyond a plain safe `SELECT`.
3. Run `execute_sql`.
4. If MCP returns `CONFIRMATION_REQUIRED`, show the exact SQL and the summary, then retry with the same `approvalId` and `userConfirmation: "CONFIRM"`.

## Example flows

Safe shell command:

```json
{
  "sessionId": "abc123",
  "command": "ps -ef | grep -i nms_1 | grep -v grep"
}
```

Custom project command that requires confirmation:

```json
{
  "sessionId": "abc123",
  "command": "smsReport"
}
```

Interactive prompt-driven command:

```json
{
  "sessionId": "abc123",
  "command": "python3 -q",
  "waitForOutputMs": 1500
}
```

Follow-up interactive input:

```json
{
  "sessionId": "abc123",
  "input": "print(2 + 2)\\n",
  "waitForOutputMs": 1000
}
```

Safe SQL query:

```json
{
  "dbSessionId": "db123",
  "sql": "select count(*) as class_count from classes"
}
```

SQL that requires confirmation:

```json
{
  "dbSessionId": "db123",
  "sql": "alter session set current_schema = NMS"
}
```

## PTY recovery flow

If a long-running command times out or an interactive program appears stuck, the PTY session stays attached on purpose so the agent can recover it instead of losing shell state.

Recommended recovery steps:

1. Call `read_output` to inspect the latest PTY output.
2. Call `read_interaction_state` when you want prompt classification instead of raw output alone.
3. Call `interrupt_session` with `ctrlC` to bring the shell back to a prompt.
4. Call `read_output` again if you want to capture the interrupt output.
5. Run a safe command such as `pwd` to confirm the shell is ready again.

This is safer than blindly starting a new session because the existing working directory, sourced environment, and any confirmed elevation state remain visible and auditable.

## Smoke test

The smoke harness verifies the SSH path end-to-end, exercises the review flow for shell and SQL, and checks PTY recovery with `interrupt_session`. It auto-confirms inside the local harness only so the test can complete; production agents must not do that.

SSH smoke test:

```powershell
$env:SSH_TEST_HOST = "your-ssh-host"
$env:SSH_TEST_PORT = "2222"
$env:SSH_TEST_USER = "your_ssh_user"
$env:SSH_TEST_PASSWORD = "your_ssh_password"
node scripts\mcp_smoke_test.mjs
```

Optional direct Oracle DB smoke test:

```powershell
$env:DB_TEST_USER = "your_db_user"
$env:DB_TEST_PASSWORD = "your_db_password"
$env:DB_TEST_CONNECT_STRING = "db-host:1521/your_service"
node scripts\mcp_smoke_test.mjs
```

Audit file example:

```powershell
Get-Content C:\ProjectNMS\NMS_MCP\mcp-audit.ndjson -Tail 20
```
