# Pi-Coding-Agent-Extensions (Unofficial)

A development workspace for creating, testing, and experimenting with [Pi](https://github.com/earendil-works/pi-coding-agent) extensions.

## Overview

This repository serves as a sandbox for building and testing custom Pi extensions. Pi extensions are custom tools and commands that extend the functionality of the Pi coding agent.  
These extensions are yours.

## Project Structure

```
.pi/extensions/     # Active extensions (loaded by Pi)
  agent-smith.ts    # Bash tool safety extension
  README.agent-smith.md  # Documentation for agent-smith
```

## Extensions

### Agent-smith

A safety layer for the `bash` tool that helps prevent accidental and malicious execution of commands leading to data loss or system damage.

See [`/.pi/extensions/README.agent-smith.md`](/.pi/extensions/README.agent-smith.md) for full documentation.

See the official project at [Pi Coding Agent](https://github.com/earendil-works/pi-coding-agent) for more information on extension development.