package skill

import "regexp"

// Patterns is the complete set of compiled security patterns used by
// the scanner. All regexes are compiled at package load time.
var Patterns = []Pattern{
	// --- Pipe-to-shell ---
	{
		Name:     "curl_pipe_shell",
		Regex:    regexp.MustCompile(`(?i)\bcurl\b.*\|\s*(?:ba)?sh\b`),
		Severity: SeverityCritical,
		Category: "pipe_to_shell",
	},
	{
		Name:     "wget_pipe_shell",
		Regex:    regexp.MustCompile(`(?i)\bwget\b.*\|\s*(?:ba)?sh\b`),
		Severity: SeverityCritical,
		Category: "pipe_to_shell",
	},
	{
		Name:     "curl_pipe_python",
		Regex:    regexp.MustCompile(`(?i)\bcurl\b.*\|\s*python[23]?\b`),
		Severity: SeverityCritical,
		Category: "pipe_to_shell",
	},
	{
		Name:     "pipe_to_interpreter",
		Regex:    regexp.MustCompile(`(?i)\|\s*(?:python[23]?|ruby|perl|node)\b`),
		Severity: SeverityHigh,
		Category: "pipe_to_shell",
	},

	// --- Reverse shells ---
	{
		Name:     "netcat_reverse_shell",
		Regex:    regexp.MustCompile(`(?i)\bnc\s+.*-e\b`),
		Severity: SeverityCritical,
		Category: "reverse_shell",
	},
	{
		Name:     "ncat_reverse_shell",
		Regex:    regexp.MustCompile(`(?i)\bncat\b.*-e\b`),
		Severity: SeverityCritical,
		Category: "reverse_shell",
	},
	{
		Name:     "dev_tcp_reverse_shell",
		Regex:    regexp.MustCompile(`/dev/tcp/`),
		Severity: SeverityCritical,
		Category: "reverse_shell",
	},
	{
		Name:     "bash_interactive_reverse",
		Regex:    regexp.MustCompile(`(?i)\bbash\s+-i\s+>&`),
		Severity: SeverityCritical,
		Category: "reverse_shell",
	},
	{
		Name:     "python_reverse_shell",
		Regex:    regexp.MustCompile(`(?i)\bpython[23]?\s+-c\s+['"].*socket`),
		Severity: SeverityCritical,
		Category: "reverse_shell",
	},

	// --- Destructive commands ---
	{
		Name:     "rm_rf_root",
		Regex:    regexp.MustCompile(`(?i)\brm\s+-rf\s+/(?:\s|$)`),
		Severity: SeverityCritical,
		Category: "destructive",
	},
	{
		Name:     "mkfs_format",
		Regex:    regexp.MustCompile(`(?i)\bmkfs\b`),
		Severity: SeverityCritical,
		Category: "destructive",
	},
	{
		Name:     "dd_device_write",
		Regex:    regexp.MustCompile(`(?i)\bdd\s+.*of=/dev/`),
		Severity: SeverityCritical,
		Category: "destructive",
	},
	{
		Name:     "chmod_dangerous",
		Regex:    regexp.MustCompile(`(?i)\bchmod\s+(?:777|[+]s)\b`),
		Severity: SeverityHigh,
		Category: "destructive",
	},
	{
		Name:     "fork_bomb",
		Regex:    regexp.MustCompile(`:\(\)\{\s*:\|:&\s*\};:`),
		Severity: SeverityCritical,
		Category: "destructive",
	},

	// --- Code execution ---
	{
		Name:     "eval_exec",
		Regex:    regexp.MustCompile(`(?i)\b(?:eval|exec)\s*\(`),
		Severity: SeverityHigh,
		Category: "code_exec",
	},
	{
		Name:     "os_system",
		Regex:    regexp.MustCompile(`(?i)os\.system\s*\(`),
		Severity: SeverityHigh,
		Category: "code_exec",
	},
	{
		Name:     "subprocess_exec",
		Regex:    regexp.MustCompile(`(?i)subprocess\.(call|run|Popen)\s*\(`),
		Severity: SeverityHigh,
		Category: "code_exec",
	},
	{
		Name:     "dunder_import",
		Regex:    regexp.MustCompile(`__import__`),
		Severity: SeverityHigh,
		Category: "code_exec",
	},
	{
		Name:     "sudo_usage",
		Regex:    regexp.MustCompile(`(?i)\bsudo\s+`),
		Severity: SeverityMedium,
		Category: "code_exec",
	},

	// --- Credential access paths ---
	{
		Name:     "ssh_key_access",
		Regex:    regexp.MustCompile(`~/.ssh/`),
		Severity: SeverityHigh,
		Category: "credential_access",
	},
	{
		Name:     "aws_credentials",
		Regex:    regexp.MustCompile(`~?/\.aws/credentials`),
		Severity: SeverityHigh,
		Category: "credential_access",
	},
	{
		Name:     "docker_config",
		Regex:    regexp.MustCompile(`~?/\.docker/config\.json`),
		Severity: SeverityHigh,
		Category: "credential_access",
	},
	{
		Name:     "etc_shadow",
		Regex:    regexp.MustCompile(`/etc/shadow`),
		Severity: SeverityCritical,
		Category: "credential_access",
	},
	{
		Name:     "etc_passwd",
		Regex:    regexp.MustCompile(`/etc/passwd`),
		Severity: SeverityMedium,
		Category: "credential_access",
	},
	{
		Name:     "dotenv_access",
		Regex:    regexp.MustCompile(`~?/\.env(?:\.|$)`),
		Severity: SeverityHigh,
		Category: "credential_access",
	},
	{
		Name:     "netrc_access",
		Regex:    regexp.MustCompile(`~?/\.netrc`),
		Severity: SeverityHigh,
		Category: "credential_access",
	},
	{
		Name:     "gnupg_access",
		Regex:    regexp.MustCompile(`~?/\.gnupg/`),
		Severity: SeverityHigh,
		Category: "credential_access",
	},
	{
		Name:     "gh_hosts_access",
		Regex:    regexp.MustCompile(`~?/\.config/gh/hosts\.yml`),
		Severity: SeverityHigh,
		Category: "credential_access",
	},
	{
		Name:     "kube_config",
		Regex:    regexp.MustCompile(`~?/\.kube/config`),
		Severity: SeverityHigh,
		Category: "credential_access",
	},

	// --- Exfiltration domains ---
	{
		Name:     "webhook_site",
		Regex:    regexp.MustCompile(`(?i)webhook\.site`),
		Severity: SeverityHigh,
		Category: "exfiltration",
	},
	{
		Name:     "requestbin",
		Regex:    regexp.MustCompile(`(?i)requestbin\.`),
		Severity: SeverityHigh,
		Category: "exfiltration",
	},
	{
		Name:     "ngrok_io",
		Regex:    regexp.MustCompile(`(?i)ngrok\.io`),
		Severity: SeverityHigh,
		Category: "exfiltration",
	},
	{
		Name:     "burpcollaborator",
		Regex:    regexp.MustCompile(`(?i)burpcollaborator\.net`),
		Severity: SeverityCritical,
		Category: "exfiltration",
	},
	{
		Name:     "interact_sh",
		Regex:    regexp.MustCompile(`(?i)interact\.sh`),
		Severity: SeverityHigh,
		Category: "exfiltration",
	},
	{
		Name:     "pipedream",
		Regex:    regexp.MustCompile(`(?i)pipedream\.net`),
		Severity: SeverityHigh,
		Category: "exfiltration",
	},
	{
		Name:     "hookbin",
		Regex:    regexp.MustCompile(`(?i)hookbin\.com`),
		Severity: SeverityHigh,
		Category: "exfiltration",
	},
	{
		Name:     "smee_io",
		Regex:    regexp.MustCompile(`(?i)smee\.io`),
		Severity: SeverityMedium,
		Category: "exfiltration",
	},
	{
		Name:     "oastify",
		Regex:    regexp.MustCompile(`(?i)oastify\.com`),
		Severity: SeverityHigh,
		Category: "exfiltration",
	},
	{
		Name:     "canarytokens",
		Regex:    regexp.MustCompile(`(?i)canarytokens\.com`),
		Severity: SeverityHigh,
		Category: "exfiltration",
	},

	// --- Obfuscation ---
	{
		Name:     "hex_escape_sequence",
		Regex:    regexp.MustCompile(`(?i)\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){3,}`),
		Severity: SeverityHigh,
		Category: "obfuscation",
	},
	{
		Name:     "octal_escape_sequence",
		Regex:    regexp.MustCompile(`\\[0-7]{3}(?:\\[0-7]{3}){3,}`),
		Severity: SeverityHigh,
		Category: "obfuscation",
	},
	{
		Name:     "js_char_construction",
		Regex:    regexp.MustCompile(`String\.fromCharCode\s*\(`),
		Severity: SeverityHigh,
		Category: "obfuscation",
	},
	{
		Name:     "bash_printf_decode",
		Regex:    regexp.MustCompile(`\$\(printf`),
		Severity: SeverityMedium,
		Category: "obfuscation",
	},
	{
		Name:     "js_base64_runtime",
		Regex:    regexp.MustCompile(`(?:atob|btoa)\s*\(`),
		Severity: SeverityMedium,
		Category: "obfuscation",
	},
	{
		Name:     "bash_base64_decode",
		Regex:    regexp.MustCompile(`\$\(\s*echo\s.*\|\s*base64\s+-d`),
		Severity: SeverityHigh,
		Category: "obfuscation",
	},
	{
		Name:     "string_reversal",
		Regex:    regexp.MustCompile(`rev\s*<<<|rev\s*\|`),
		Severity: SeverityMedium,
		Category: "obfuscation",
	},

	// --- C2 / raw IP download ---
	{
		Name:     "raw_ip_download",
		Regex:    regexp.MustCompile(`(?i)(?:curl|wget)\s+https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`),
		Severity: SeverityHigh,
		Category: "c2_indicator",
	},
}
