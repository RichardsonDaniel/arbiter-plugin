# Arbiter plugin

Security checks and plain-language reports for apps built with AI, as a plugin for Claude Code and Codex. It adds the Arbiter server (so your coding tool can ask "is this safe to ship?"), a `/arbiter:scan` command, a skill that explains the reports, and guard hooks that stop destructive database commands and risky edits before they run.

## Claude Code

```
claude plugin marketplace add RichardsonDaniel/arbiter-plugin
claude plugin install arbiter@arbiter
```

## Codex

```
codex plugin marketplace add RichardsonDaniel/arbiter-plugin
codex plugin add arbiter@arbiter
```

Codex runs a plugin's hooks only after you have reviewed and trusted them: start a new Codex session, type `/hooks` and trust the three Arbiter hooks.

The server address is `https://api.arbiterscan.com/mcp`; sign in with your email when the tool asks. Set `ARBITER_MCP_URL` to point the plugin at another server. More at https://arbiterscan.com.

This repository is published from the Arbiter product repository and receives every change made there.

## Licence

The plugin files in this repository (the skill, command, hooks and Codex snippet) are under the MIT licence; see LICENSE. The Arbiter service they connect to is not part of this repository and is covered by the terms at https://arbiterscan.com/terms/.
