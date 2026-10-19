---
description: Scan this project with Arbiter and summarise what to fix first
---

Run an Arbiter security scan of the current project: call the `scan_project` tool from the arbiter MCP server with the current folder (or, on the hosted server, this repository's URL). If it reports the scan is still running, wait about thirty seconds and call `get_scan` with the id.

For a deeper look, when the user asks for one or after a quick scan comes back clean on an app that handles money, roles or uploads: call `start_scan` with `deep: true`. It reads the files that must be read together the way a security reviewer would, takes a few minutes and uses one of the workspace's monthly allowance; poll `get_scan` with the id about once a minute, and it reports how many surfaces have been read.

Then give the user a short plain-English summary: whether it is safe to ship, the top three things to fix in order, and what was not checked. If parts were not checked, ask for the missing input (deployed URL, Supabase connection) rather than calling the app safe. Include the full report link when there is one. Offer to walk through the first fix. Do not change any file until the user agrees.
