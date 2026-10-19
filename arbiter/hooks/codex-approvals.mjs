// Approvals for the Codex edit guard. Codex's PreToolUse hooks can deny a tool call but cannot ask the person
// ("ask" is parsed and not supported), so the guard denies with a short code and the person allows the edit by
// sending a message made only of `arbiter allow <code>` lines. A UserPromptSubmit hook (codex-allow.mjs) sees
// only what the person types, so the agent cannot approve its own edit through the chat.
//
// Each code covers one finding on one file for one exact result of the edit (a hash of the file's text after it),
// in one session. An approval is used up by the edit it allowed, and an unused one lapses after an hour.
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
// The whole message must be allow lines, so quoting the agent's pause message back does not approve anything.
const ALLOW_ONLY = /^\s*(arbiter\s+allow\s+[0-9a-f]{6}[\s,.;]*)+$/i
const ALLOW_CODE = /\barbiter\s+allow\s+([0-9a-f]{6})\b/gi

/** The codes in a message that consists only of allow lines; [] for any other message. */
export function allowCodes(prompt) {
  if (!ALLOW_ONLY.test(prompt)) return []
  return [...prompt.matchAll(ALLOW_CODE)].map((m) => m[1].toLowerCase())
}

/** The code the person types to allow this finding on this file, for this exact post-edit text, in this session. */
export function approvalCode(session, file, reason, after) {
  const afterHash = createHash('sha256').update(after).digest('hex')
  return createHash('sha256').update(`${session}\n${file}\n${reason}\n${afterHash}`).digest('hex').slice(0, 6)
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

function save(all) {
  mkdirSync(DIR, { recursive: true })
  const tmp = `${FILE}.${process.pid}`
  writeFileSync(tmp, JSON.stringify(all))
  renameSync(tmp, FILE)
}

const key = (session, code) => `${session}:${code.toLowerCase()}`

export function isApproved(session, code) {
  return Boolean(load()[key(session, code)])
}

/** Uses up approvals once the edit they allowed goes ahead. */
export function consume(session, codes) {
  const all = load()
  for (const code of codes) delete all[key(session, code)]
  save(all)
}

export function approve(session, codes) {
  const all = load()
  for (const code of codes) all[key(session, code)] = { expires: Date.now() + TTL_MS }
  save(all)
}
