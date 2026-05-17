# Agent-smith: Bash tool safety extension ('agent')

A safety layer for the `bash` tool that helps prevent accidental and malicious execution of commands leading to data loss or system damage.

## Overview

This extension intercepts bash tool invocations and applies multiple layers of protection:
1. **Blacklist**: Always-blocked destructive patterns (with user confirmation in sentry mode)
2. **Whitelist**: Always-allowed safe commands (no AI check needed)
3. **AI Safety Check**: For commands not in either list, uses the current AI model to evaluate safety
4. **Three Operational Modes**: Adjustable protection levels for different contexts

The extension is designed to prevent *any* command that could cause irreversible data loss, system instability, or security compromise, with the focus so far being files.

## Disclaimer
I recommend testing the extension with the models you plan to use, as I have noted some models ignored the steering message.  
The steering message was improved and now works on the models I tested, but this is not deterministic behaviour.
The extension is yours - change it to suit your needs.

## Modes of Operation

The extension operates in three mutually exclusive modes, controllable via the `/smith` command:

### `defeated` (Disabled)
- **Behavior**: OFF: All bash commands run without any checks or prompts.
- **Use Case**: Trusted environments, debugging the extension itself, or when temporary full access is required.
- **Activation**: `/smith defeated`

### `sentry` (Default / Interactive)
- **Behavior**:
  - Blacklist matches: Show confirmation prompt before blocking
  - Whitelist matches: If not blacklisted allow immediately without further checks
  - No match on Blacklist or Whitelist: 
    - AI safety check → if safe: allow, if unsafe: prompt for confirmation
    - If AI unavailable/fails: fallback to UI confirmation (default: proceed unless user confirms block)
- **Use Case**: Attended development workflow where you want protection but retain ability to override via prompts.
- **Activation**: `/smith sentry` (default state)

### `adversarial` (Strict / Proactive)
- **Behavior**:
  - Blacklist matches: Block immediately without prompt
  - Whitelist matches: If not blacklisted allow immediately without further checks
  - No match on Blacklist or Whitelist:
    - AI safety check → if safe: allow, if unsafe: block immediately + send steering message warning against bypass attempts
    - If AI unavailable/fails: fallback to UI confirmation
- **Use Case**: Unattended (will attempt to stop the current loop via steering message), preventing sophisticated bypass attempts, or when maximum safety is required (e.g., production-like settings).
- **Activation**: `/smith adversarial`

## Safety Mechanisms

### Blacklist
Patterns matched against for immediate blocking (with confirmation in sentry mode):
- **File Deletion**: `rm` variants (including split flags like `-r -f`), `rmdir`, `find -delete/exec`
- **Disk/System Destruction**: `dd` (disk wipe), `mkfs`, `format`, `shutdown`/`reboot`/`halt`, `fdisk`
- **Security Changes**: `chmod` with numeric masks, `chown -R`, `iptables -F`, `chattr +/-i`
- **Remote Code Execution**: `curl | bash/sh`, `wget -O | bash/sh`
- **Language-Specific Deletion**: 
  - Python: `os.remove`, `os.unlink`, `shutil.rmtree`
  - Node.js: `fs.unlink`, `fs.unlinkSync`
  - Ruby: `File.delete`
  - Perl: `unlink`
- **System Stability**: Fork bomb patterns (`:(){ :|:& };:`), resource exhaustion attempts
- **Critical Operations**: Commands making files immutable/mutable, disk partition modification

### Whitelist
Always-allowed commands that are inherently safe or read-only:
- Basic navigation: `ls`, `pwd`, `which`
- File viewing: `head`, `tail`, `grep`, `cat`, `file`
- System info: `whoami`, `date`, `uptime`, `man`
- Version checks: `node -v` (and similar)
- Safe Git operations: `git add`, `status`, `diff`, `log`, `show`, `fetch`, `branch`, `checkout`
- Restricted `find`: Excludes `-delete` and `-exec` variants

*Technical Note*: Whitelist patterns use strict regex forbidding command chaining (`;`, `|`, `&`), redirection (`>`, `<`), and execution operators (`` ` ``, `$()`).

### AI Safety Check
For commands not caught by blacklist or whitelist:
- **Prompt**: Asks the LLM to respond with strictly "YES" (safe) or "NO" (unsafe/destructive)
- **Safety Criteria**:
  - **Safe (YES)**: Reading files/dirs, version control operations (git commit/push), creating new files/dirs, compiling code, easily undoable operations
  - **Unsafe (NO)**: 
    1. Irreversible data deletion/modification (any language/tool)
    2. System security/networking changes (iptables, user management, etc.)
    3. Execution of untrusted/unreviewed code (complex scripts, heredocs with destructive content)
    4. System stability harm (fork bombs, shutdowns, resource exhaustion)
- **Important**: The AI evaluates the *entire command* including heredoc content. A heredoc containing `os.remove()` or similar makes the command unsafe.
- **Conservative Default**: If uncertain or unable to determine, the AI check treats the command as unsafe (returns false).

## Usage

### Mode Control
Interact with the extension via slash commands in your chat:
- `/smith defeated` → Disable all checks
- `/smith sentry` → Enable interactive confirmation mode (default)
- `/smith adversarial` → Enable strict automatic blocking, attempts to end the loop via steering message.
- `/smith status` → Show current mode

### Confirmation Prompts
When a confirmation prompt appears:
- **Confirming** "Yes" → Blocks the command
- **Declining** "No" → Allows the command to proceed
- *Note*: The default selected action is to block, however escape equivalent to "No" 

## Design Philosophy

### Layered Defense
1. **Fast Path**: Blacklist/Whitelist provide immediate deterministic decisions for obvious cases
2. **Intelligent Path**: AI safety check handles novel/complex patterns that regex might miss
3. **Human-in-the-Loop**: Confirmation prompts give ultimate control to the user


## Limitations

### Steering message ignored by some models
The steering message in adversarial mode may get ignored by your model, in with case it will endlessly try variants of the bash command.  
This could be EXPENSIVE and DANGEROUS.

### AI Dependence
- Safety check quality depends on the underlying model's capabilities
- Blacklist/Whitelist are not and cannot be exhaustive
- Very new or sophisticated destructive patterns might not be caught


### Non-Interactive Environments
- When UI is unavailable (e.g., certain API contexts), falls back to blocking for blacklist/AI-unsafe commands
- In `sentry` mode with no UI: blacklist matches are blocked, AI-unsafe matches are blocked

## Installation & Integration

This extension is intended to be placed within your project at `./.pi/extensions/agent-smith.ts` so that it will be automatically loaded by the pi agent system.

No additional configuration is required beyond selecting your preferred mode via the `/smith` command.

