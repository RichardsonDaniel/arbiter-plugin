---
description: Scan this project with Arbiter and summarise what to fix first
---

Run an Arbiter security scan of the current project: call the `scan_project` tool from the arbiter MCP server with the current folder (or, on the hosted server, this repository's URL). If it reports the scan is still running, wait about thirty seconds and call `get_scan` with the id.

Then give the user a short plain-English summary: whether it is safe to ship, the top three things to fix in order, and what was not checked. Offer to walk through the first fix. Do not change any file until the user agrees.
