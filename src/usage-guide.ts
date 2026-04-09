export interface UsageGuideToolInfo {
  tool: string;
  useWhen: string;
  avoidWhen?: string;
  notes?: string[];
}

export interface UsageGuide {
  summary: string;
  preferredStyle: string[];
  commandStyle: string[];
  confirmationStyle: string[];
  sudoStyle: string[];
  secretHandling: string[];
  antiPatterns: string[];
  toolGuidance: UsageGuideToolInfo[];
  escalationHints: string[];
  livePolicyReference: {
    tool: string;
    guidance: string;
  };
}

const TOOL_GUIDANCE: UsageGuideToolInfo[] = [
  {
    tool: "read_usage_guide",
    useWhen: "You need MCP-specific usage guidance, preferred operating style, or anti-pattern reminders for this server.",
    notes: [
      "Use this first when you are unsure how this MCP expects commands to be structured.",
    ],
  },
  {
    tool: "ssh_connect",
    useWhen: "Open an SSH session for host diagnostics or command execution.",
    notes: [
      "Pass LDAP-style login fields such as username, hostUser, or ldapUser for the initial SSH session.",
      "Pass encoded secret fields when available; MCP decodes them internally.",
    ],
  },
  {
    tool: "ssh_connect_target_session",
    useWhen:
      "Open an SSH session and immediately adopt a non-root target user so later diagnostics do not have to repeat sudo.",
    notes: [
      "Prefer this for NMS log analysis when you know the project or admin target user up front.",
      "Use targetSwitchMethod to choose between sudo su - <user> and sudo -iu <user>.",
    ],
  },
  {
    tool: "review_command",
    useWhen: "You want one command reviewed before deciding whether to run it.",
    avoidWhen: "You already know you need a related multi-command check on the same host.",
  },
  {
    tool: "review_command_batch",
    useWhen: "You have a related set of standalone commands and want one combined decision or confirmation path.",
    notes: [
      "Prefer this for human-style check sequences such as smsReport, ps, grep, and find.",
    ],
  },
  {
    tool: "execute_command",
    useWhen: "Run one focused non-interactive command.",
    avoidWhen: "The command will prompt, open a REPL, or you really mean to run several related checks.",
  },
  {
    tool: "execute_command_batch",
    useWhen: "Run several related standalone commands sequentially on one session with one shared review/confirmation path.",
    notes: [
      "This is the preferred tool for a diagnostic checklist on one host.",
      "Keep each command narrow and readable instead of bundling them into one shell script.",
    ],
  },
  {
    tool: "start_interactive_command",
    useWhen: "A command is truly interactive or likely to prompt for input.",
    avoidWhen: "The command is just a normal read-only diagnostic that can run with execute_command or execute_command_batch.",
  },
  {
    tool: "send_interaction_input",
    useWhen: "Continue an already interactive PTY flow after checking the prompt state.",
  },
  {
    tool: "read_interaction_state",
    useWhen: "Inspect what the interactive shell is waiting for before sending more input.",
  },
  {
    tool: "read_policy",
    useWhen: "You need the live server policy and rule configuration, not just usage guidance.",
  },
  {
    tool: "oracle_connect",
    useWhen: "Open an Oracle DB session for read-only diagnostics or approved SQL execution.",
    notes: [
      "Prefer the read-only application schema first unless the user explicitly needs a higher-privilege account.",
    ],
  },
  {
    tool: "review_sql",
    useWhen: "Review SQL safety before execution when it is not an obviously safe read-only query.",
  },
  {
    tool: "execute_sql",
    useWhen: "Run read-only SQL after connection, or an approved SQL statement after review/confirmation.",
    notes: [
      "Prefer one exact SELECT statement at a time instead of multi-statement SQL blocks.",
    ],
  },
  {
    tool: "list_nms_guides",
    useWhen: "Browse Oracle Utilities Network Management System documentation versions and guide titles from the live Oracle docs site.",
    notes: [
      "Use this first when you need the right version, guide title, slug, or cached local PDF path.",
    ],
  },
  {
    tool: "get_nms_guide_pdf",
    useWhen: "Resolve one Oracle Utilities Network Management System guide to a cached local PDF path, downloading it when necessary.",
    notes: [
      "Pass the NMS version plus a guide title, slug, or PDF filename fragment.",
      "Prefer this over handing the AI a raw Oracle docs URL.",
    ],
  },
  {
    tool: "read_audit_log",
    useWhen: "You need evidence of what MCP reviewed or executed.",
  },
];

const USAGE_GUIDE: UsageGuide = {
  summary:
    "Use this MCP like a careful human operator: small standalone commands, clear host/user context, and grouped confirmation only when it helps.",
  preferredStyle: [
    "Prefer standalone read-only commands over one large bundled bash or shell script block.",
    "For related checks on one host, prefer review_command_batch and execute_command_batch.",
    "When repeated checks should run as one project or admin user, prefer ssh_connect_target_session over repeating sudo on every command.",
    "Keep each command focused on one question so the output is easy to inspect and summarize.",
    "For Oracle NMS product documentation, prefer list_nms_guides and get_nms_guide_pdf over manual website scraping.",
  ],
  commandStyle: [
    "Good pattern: hostname, whoami, smsReport, ps, grep, find, tail, ss.",
    "Prefer grep -n, head, tail, sort, and narrow find filters so the output stays readable.",
    "Avoid giant quoted bash -lc bundles unless the command truly requires a one-shot shell wrapper.",
    "For SQL, prefer one exact read-only statement at a time instead of multi-statement blocks.",
  ],
  confirmationStyle: [
    "Do not ask for confirmation repeatedly when one shared confirmation for a related command batch is enough.",
    "If confirmation is required, show the exact command or command set plus the consequence summary.",
    "Never self-confirm.",
  ],
  sudoStyle: [
    "For NMS-style access, prefer LDAP login first and then sudo to the target project or admin user instead of attempting direct target-user login.",
    "When you already know the target account, prefer ssh_connect_target_session so later checks can run directly as that user.",
    "Exact target-user handoffs such as sudo su - esb8 or sudo -iu oracle can be started with start_interactive_command without an extra CONFIRM prompt.",
    "Prefer direct target-user commands such as sudo -u esb8 smsReport or sudo -u esb8 grep ...",
    "Exact read-only target-user diagnostics such as sudo -u esb8 whoami, ps, grep, find, or smsReport previews can auto-run without extra confirmation.",
    "Do not add source ~/.bashrc, source ~/.profile, or similar setup after sudo unless the command truly depends on extra environment initialization.",
    "Use interactive sudo flows only when a direct one-shot sudo command is not enough.",
  ],
  secretHandling: [
    "Encoded secret fields are preferred when present and are decoded only inside MCP.",
    "Never print raw or decoded secrets in messages, plans, or logs.",
    "Pass sudo-capable credentials only when they are actually needed.",
  ],
  antiPatterns: [
    "Do not bundle many unrelated checks into a single shell script when a short command batch is clearer.",
    "Do not source login scripts after sudo by default.",
    "Do not choose interactive flows for simple read-only checks.",
    "Do not echo secrets back to the user.",
  ],
  toolGuidance: TOOL_GUIDANCE,
  escalationHints: [
    "Use read_policy when the live allow/approval/block rules matter.",
    "Use review_command or review_command_batch when you are unsure whether a command set will need confirmation.",
    "Use start_interactive_command only after deciding the command is truly interactive.",
  ],
  livePolicyReference: {
    tool: "read_policy",
    guidance:
      "This usage guide explains preferred behavior. Call read_policy for the active server-side policy, approval categories, and allow/deny rules.",
  },
};

export function getUsageGuide(): UsageGuide {
  return USAGE_GUIDE;
}
