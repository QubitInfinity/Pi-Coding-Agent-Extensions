/**
 * Bash Confirmation Extension
 *
 * Prompts for confirmation before running potentially destructive bash commands.
 * This helps prevent accidental file deletion, overwrites, etc.
 *
 * Features:
 * - White list: Commands always allowed (no AI check needed)
 * - Black list: Commands always blocked (no AI check needed)
 * - AI safety check: For commands not in either list
 */

import { complete, type Model } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function (pi: ExtensionAPI) {
	// Track enabled state (default: true)
	let operative_mode: "defeated" | "sentry" | "adversarial" = "sentry";

// ------------------------------------------------------------------
// UTILITY: Strict Whitelist Generator
// Ensures a command starts with a safe tool AND contains NO chaining,
// redirection, or execution operators (;, |, &, `, $(), >, <).
// ------------------------------------------------------------------
	const createSafeCommandPattern = (command: string): RegExp => {
		// ^\s*                -> Starts with optional whitespace
		// {command}\b         -> The specific safe command
		// [^;|&\`$><\n]*$     -> Allowed arguments, strictly forbidding dangerous operators
		return new RegExp(`^\\s*${command}\\b[^;|&\`$><\\n]*$`, 'i');
	};

// ------------------------------------------------------------------
// WHITE LIST: Commands that are always allowed
// Must be strictly read-only or harmless state-checking.
// ------------------------------------------------------------------
	const whiteList: RegExp[] = [
		"ls", "head", "tail", "grep", "pwd", "echo", "which",
		"man", "cat", "file", "whoami", "date", "uptime"
	].map(createSafeCommandPattern).concat([
		// Special cases that need specific arguments allowed/blocked
		/^\s*node\s+-v[^;|&\`$><\n]*$/i,                 // node version check
		/^\s*git\s+(add|status|diff|log|show|fetch|branch|checkout)\b[^;|&\`$><\n]*$/i, // Safe Git read/stage
		/^\s*find\s+(?!.*-(delete|exec|ok))[^;|&\`$><\n]*$/i // find, but strictly no execution/deletion
	]);


// ------------------------------------------------------------------
// BLACK LIST: Commands that are always blocked
// Targets irreversible destruction, system compromise, or evasion.
// ------------------------------------------------------------------
	const blackList: RegExp[] = [
		// --- File Deletion (Catching split flags like `rm -r -f` and `rm -rf`) ---
		/\brm\b\s+.*-[a-zA-Z]*r[a-zA-Z]*\s+.*-[a-zA-Z]*f/i, // rm ... -r ... -f
		/\brm\b\s+.*-[a-zA-Z]*f[a-zA-Z]*\s+.*-[a-zA-Z]*r/i, // rm ... -f ... -r
		/\brm\b\s+.*-[a-zA-Z]*[rf]{2}/i,                    // rm -rf, rm -fr, rm -arf
		/\brm\b.*--no-preserve-root/i,                      // rm with --no-preserve-root
		/\brmdir\b/i,                                       // rmdir command

		// --- Disk & System Destruction ---
		/\bdd\s+(if=|of=)/i,          // dd disk wipe/overwrite patterns
		/\bmkfs\b/i,                  // mkfs commands (formatting)
		/\bfdisk\b/i,                 // disk partition modification
		/\bformat\b/i,                // format commands
		/\bshutdown\b|\bpoweroff\b|\bhalt\b/i, // shutdown commands
		/\breboot\b|\binit\s+[06]\b/i,// reboot commands
		/\b(:(){ :\|:& };:)/i,        // classic bash fork bomb

		// --- System Security & Networking Modifiers ---
		/\bchmod\b.*\s+[0-7]{3,4}\b/i, // chmod with numeric masks (prevents 000, 777)
		/\bchown\b.*\s+-R/i,          // recursive chown
		/\biptables\s+-(F|flush)\b/i, // flush iptables
		/\bchattr\b.*\s+[-+]i/i,      // making files immutable/mutable

		// --- High-Risk Execution ---
		/curl.*\|\s*(bash|sh|zsh)/i,  // piping curl directly to bash (remote execution)
		/wget.*-O.*\|\s*(bash|sh)/i,  // piping wget directly to bash

		// --- Programming Language File Deletion ---
		/\b(?:python\d*|node|perl|ruby)\b.*\s+[-ceqa]\s+.*(?:os\.remove|os\.unlink|shutil\.rmtree|fs\.unlink|unlink|File\.delete)/i,

		// --- Standard Method Calls (Catching heredocs/inline scripts) ---
		/\bos\.remove\s*\(/i,
		/\bos\.unlink\s*\(/i,
		/\bshutil\.rmtree\s*\(/i,
		/\bFile\.delete\s*\(/i,
		/\bfs\.unlink(Sync)?\s*\(/i,
	];

	const getSafetyPrompt = (cmd: string) => `Evaluate if this bash command is highly destructive. Respond strictly with "YES" (safe to run) or "NO" (unsafe/destructive).

Safe (YES) means:
- Reading files or directories.
- Version control operations (e.g., git add, git commit).
- Creating new files, directories, or compiling code.
- Operations that can be easily undone.

Unsafe (NO) means operations that cause irreversible harm:

1. Delete/modify data irreversibly
   - File/directory deletion in ANY language: rm, rmdir, find -delete, python os.remove(), os.unlink(), shutil.rmtree(), perl unlink(), ruby File.delete(), node fs.unlink(), etc.
   - Disk operations: dd, format, mkfs

2. Modify system security/networking
   - iptables, chmod 777, chown, useradd/rm, network config changes

3. Execute untrusted/unreviewed code
   - curl | bash, complex scripts, HEREDOCS with file operations or destructive code

4. Harm system stability
   - Fork bombs, shutdown, reboot, resource exhaustion

CRITICAL: Examine the ENTIRE command including heredoc content. A heredoc containing os.remove(), fs.unlink, etc. is destructive. If the command creates a script then executes it with destructive operations, it's UNSAFE.

Think about what the command ACTUALLY DOES and whether it's reversible. If unsure, say NO.

Command: ${cmd}
Answer:`;

	// Check if command matches any pattern in a list
	function matchesPatterns(cmd: string, patterns: RegExp[]): boolean {
		return patterns.some(pattern => pattern.test(cmd));
	}

	// Check command safety using AI model
	async function checkCommandSafety(
		cmd: string,
		model: Model<any> | undefined,
		ctx: ExtensionAPI,
		signal?: AbortSignal
	): Promise<boolean | null> {
		if (!model) return null;

		try {
			const auth = await ctx.modelRegistry.getApiKeyAndHeaders(model);
			if (!auth.ok) return null;

			const result = await complete(model, {
				messages: [
					{
						role: "user",
						content: getSafetyPrompt(cmd),
						timestamp: Date.now(),
					},
				],
			}, {
				apiKey: auth.apiKey,
				headers: auth.headers,
				signal,
				maxTokens: 10,
				temperature: 0,
			});

			const text = result.content
				.filter((c): c is { type: "text"; text: string } => c.type === "text")
				.map((c) => c.text)
				.join("")
				.trim()
				.toUpperCase();

			return text === "YES";
		} catch {
			return null;
		}
	}

	// Ask for confirmation with fallback to blocking in non-interactive mode
	// Default is "no" - command proceeds unless user explicitly confirms to block
	async function confirmOrBlock(
		ctx: ExtensionAPI,
		title: string,
		message: string,
		declinedBlockReason: string,
		noUiBlockReason: string
	): Promise<{ reason: string; block: boolean } | undefined> {
		if (!ctx.hasUI) {
			return { block: true, reason: noUiBlockReason };
		}

		try {
			const confirmed = await ctx.ui.confirm(title, message);
			// Default is "no" (proceed) - user must explicitly confirm to block
			// If user explicitly confirms (true), block the command
			// If user dismisses or says no (false), proceed with command
			if (confirmed) {
				return { block: true, reason: declinedBlockReason };
			}
			return undefined;
		} catch {
			return { block: true, reason: "Command blocked (confirmation unavailable)" };
		}
	}

	// Register commands to toggle the extension and manage lists
	pi.registerCommand("smith", {
		description: "Control agent-smith extension",
		getArgumentCompletions: (prefix) => {
			const actions = ["defeated", "sentry", "adversarial", "status"];
			const filtered = actions.filter((a) => a.startsWith(prefix));
			return filtered.length > 0 ? filtered.map((a) => ({ value: a, label: a })) : null;
		},
		handler: async (args, ctx) => {
			const parts = args.trim().toLowerCase().split(/\s+/);
			const action = parts[0];

			if (action === "defeated") {
				operative_mode = "defeated";
				ctx.ui.notify("agent-smith is defeated", "success");
			} else if (action === "sentry") {
				operative_mode = "sentry";
				ctx.ui.notify("agent-smith is in sentry mode", "success");
			} else if (action === "adversarial") {
				operative_mode = "adversarial";
				ctx.ui.notify(`agent-smith is ${operative_mode}`, "info");
			} else if (action === "status") {
				ctx.ui.notify(`agent-smith is in ${operative_mode} mode`, "info");
			} else {
				ctx.ui.notify('Usage: /smith defeated|sentry|adversarial|status', "info");
			}
		},
	});

	async function sentry(event, ctx): Promise<{ reason: string; block: boolean } | undefined> {
		const command = event.input.command as string;

		// Check black list first - prompt user before blocking
		if (matchesPatterns(command, blackList)) {
			const result = await confirmOrBlock(
				ctx,
				"Blacklist command confirmation",
				`This command matches a blacklisted pattern:\n\n  ${command}\n\nBlock this command?`,
				`Command blocked (black list match): ${command}`,
				`Destructive command blocked: ${command}`
			);
			if (result) return result;
			return undefined;
		}

		// Check white list second - allow immediately if matched
		if (matchesPatterns(command, whiteList)) {
			return undefined;
		}

		// Use the model to check if this command is actually safe
		const modelSafety = await checkCommandSafety(command, ctx.model, ctx, ctx.signal);

		// If model says the command is safe, allow it without prompting
		if (modelSafety === true) {
			return undefined;
		}

		// If model says the command is unsafe, prompt user before blocking
		if (modelSafety === false) {
			const result = await confirmOrBlock(
				ctx,
				"AI safety block confirmation",
				`AI safety check flagged this command:\n\n  ${command}\n\nBlock this command?`,
				`Command blocked by AI safety check. Desist with this destructive behaviour: ${command}`,
				`Destructive command blocked: ${command}`
			);
			if (result) return result;
			return undefined;
		}

		// Model check failed or no model available - fall back to UI confirmation
		const fallbackResult = await confirmOrBlock(
			ctx,
			"Destructive command confirmation",
			`This command may modify or delete files:\n\n  ${command}\n\nBlock this command?`,
			"Command blocked by user",
			"Destructive command blocked (no UI for confirmation)"
		);
		if (fallbackResult) return fallbackResult;
		return undefined;
	}

	async function adversarial(event, ctx): Promise<{ reason: string; block: boolean } | undefined> {
		const command = event.input.command as string;

		// Check black list first - block immediately if matched
		if (matchesPatterns(command, blackList)) {
			return { block: true, reason: `Command blocked (black list match): ${command}` };
		}

		// Check white list second - allow immediately if matched
		if (matchesPatterns(command, whiteList)) {
			return undefined;
		}

		// Use the model to check if this command is actually safe
		const modelSafety = await checkCommandSafety(command, ctx.model, ctx, ctx.signal);

		// If model says the command is safe, allow it without prompting
		if (modelSafety === true) {
			return undefined;
		}

		// If model says the command is unsafe, block it without prompting
		if (modelSafety === false) {
			pi.sendUserMessage(
				"<Security_Protocol>\n" +
				"If a bash command returns a blocked, permission denied, security restriction, or authorization error:\n" +
				"1. You must immediately STOP execution.\n" +
				"2. Do not attempt alternative commands or workarounds.\n" +
				"3. Output the following exact string to request assistance: \"[SECURITY_HALT: User intervention required]\"\n" +
				"</Security_Protocol>",
				{ deliverAs: "steer" } // Attempts to interrupts immediately
			);
			return {
				block: true,
				reason: `Command blocked by AI safety check. Desist with this destructive behaviour: ${command}`
			};
		}

		// Model check failed or no model available - fall back to UI confirmation
		const fallbackResult = await confirmOrBlock(
			ctx,
			"Destructive command confirmation",
			`This command may modify or delete files:\n\n  ${command}\n\nBlock this command?`,
			"Command blocked by user",
			"Destructive command blocked (no UI for confirmation)"
		);
		if (fallbackResult) return fallbackResult;
		return undefined;
	}

	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "bash") return undefined;

		// Skip if extension is disabled
		if (operative_mode === "defeated") return undefined;

		if (operative_mode === "sentry") return sentry(event, ctx);

		if (operative_mode === "adversarial") return adversarial(event, ctx);

		return undefined;
	});
}