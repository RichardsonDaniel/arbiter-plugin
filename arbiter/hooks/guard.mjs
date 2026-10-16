#!/usr/bin/env node
// Arbiter guard hook: blocks the shell commands that most often wipe an AI-built app's data, and pushes
// that would commit a secret. Exit 2 blocks the call with a one-line reason; exit 0 lets it through.
// Set ARBITER_GUARD=off to disable.
import { execFileSync } from 'node:child_process'

if (process.env.ARBITER_GUARD === 'off') process.exit(0)

const RULES = [
  { re: /\bDROP\s+(TABLE|SCHEMA|DATABASE)\b/i, why: 'drops a table, schema or database', instead: 'rename it or back it up first; dropping deletes the data for good' },
  { re: /\bDROP\s+COLUMN\b/i, why: 'drops a column', instead: 'copy the data aside or rename the column; a dropped column cannot be recovered' },
  { re: /\bTRUNCATE\b/i, why: 'empties a table', instead: 'delete the rows you mean with a WHERE clause, after a backup' },
  { re: /\bDELETE\s+FROM\s+[\w."]+\s*(;|$|\)|'|")/i, why: 'deletes every row in a table (no WHERE)', instead: 'add a WHERE clause, or back the table up first' },
  { re: /\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/i, why: 'switches row-level security off', instead: 'add the policy the app needs instead of removing the protection' },
  { re: /\bsupabase\s+db\s+reset\b/i, why: 'resets the Supabase database', instead: 'run the one migration you need, or reset a branch, not production' },
  { re: /\bprisma\s+(migrate\s+reset|db\s+push\s+--force-reset)\b/i, why: 'resets the database through Prisma', instead: 'create a migration for the change you need' },
  { re: /\bfirebase\s+firestore:delete\b.*(--all-collections|-r\b)/i, why: 'deletes Firestore collections', instead: 'delete the single document or collection you mean, after an export' },
  { re: /\brm\s+-rf\s+(\/|~|\.|\*)(\s|$)/, why: 'removes a whole directory tree', instead: 'name the files you mean' },
]
const SECRET_SHAPES = [/\b[sr]k_(live|test)_[0-9A-Za-z]{16,}\b/, /\bsb_secret_[0-9A-Za-z_-]{20,}\b/, /\bsk-ant-[0-9A-Za-z_-]{20,}\b/, /\bsk-(proj-)?[0-9A-Za-z_-]{32,}\b/, /\bAKIA[0-9A-Z]{16}\b/, /\bghp_[0-9A-Za-z]{30,}\b/, /\bre_[0-9A-Za-z]{20,}\b/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./]

let input = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (c) => (input += c))
process.stdin.on('end', () => {
  let command = ''
  try {
    const parsed = JSON.parse(input)
    command = String(parsed.tool_input?.command ?? '')
  } catch {
    process.exit(0)
  }
  for (const r of RULES) {
    if (r.re.test(command)) {
      process.stderr.write(`Arbiter guard: this command ${r.why}. Safer: ${r.instead}. (Set ARBITER_GUARD=off to override.)\n`)
      process.exit(2)
    }
  }
  if (/\bgit\s+push\b/.test(command)) {
    try {
      const diff = execFileSync('git', ['diff', '--cached', '--no-color'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      const hit = SECRET_SHAPES.find((s) => s.test(diff))
      if (hit) {
        process.stderr.write('Arbiter guard: the staged changes contain something shaped like a secret key. Move it to an environment variable before pushing. (Set ARBITER_GUARD=off to override.)\n')
        process.exit(2)
      }
    } catch {
      /* not a git repo or nothing staged */
    }
  }
  process.exit(0)
})
