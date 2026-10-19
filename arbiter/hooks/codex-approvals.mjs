// Approvals for the Codex edit guard. Codex's PreToolUse hooks can deny a tool call but cannot ask the person
// ("ask" is parsed and not supported), so the guard denies with a short code and the person allows the edit by
// typing `arbiter allow <code>` themselves. A UserPromptSubmit hook (codex-allow.mjs) sees only what the person
// types, so the agent cannot approve its own edit through the chat. Approvals last an hour, for that session.
//
// The file lives outside the project (ARBITER_STATE_DIR, default ~/.arbiter), which Codex's workspace-write
// sandbox does not let the agent's shell commands write to.
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync, renameSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const DIR = process.env.ARBITER_STATE_DIR ?? join(homedir(), '.arbiter')
const FILE = join(DIR, 'codex-approvals.json')
const TTL_MS = 60 * 60 * 1000
export const ALLOW_RE = /\barbiter\s+allow\s+([0-9a-f]{6})\b/gi

/** The code the person types to allow this exact finding on this file in this session. */
export function approvalCode(session, file, reason) {
  return createHash('sha256').update(`${session}\n${file}\n${reason}`).digest('hex').slice(0, 6)
}

function load() {
  try {
    const all = JSON.parse(readFileSync(FILE, 'utf8'))
    const now = Date.now()
    return Object.fromEntries(Object.entries(all).filter(([, v]) => v && v.expires > now))
  } catch {
    return {}
  }
}

export function isApproved(session, code) {
  return Boolean(load()[`${session}:${code.toLowerCase()}`])
}

export function approve(session, codes) {
  const all = load()
  for (const code of codes) all[`${session}:${code.toLowerCase()}`] = { expires: Date.now() + TTL_MS }
  mkdirSync(DIR, { recursive: true })
  const tmp = `${FILE}.${process.pid}`
  writeFileSync(tmp, JSON.stringify(all))
  renameSync(tmp, FILE)
}
