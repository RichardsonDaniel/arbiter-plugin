#!/usr/bin/env node
// Arbiter guard hook: blocks the shell commands that most often wipe an AI-built app's data, and pushes
// that would publish a secret. Exit 2 blocks the call with a one-line reason; exit 0 lets it through.
// The same file serves Claude Code (PreToolUse on Bash) and Codex (PreToolUse on Bash, which covers its shell and
// exec_command tools): both send tool_input.command and both treat exit 2 with a reason on stderr as a block.
// Set ARBITER_GUARD=off to disable.
import { execFileSync } from 'node:child_process'

if (process.env.ARBITER_GUARD === 'off') process.exit(0)

const RULES = [
  { re: /\bDROP\s+(TABLE|SCHEMA|DATABASE)\b/i, why: 'drops a table, schema or database', instead: 'rename it or back it up first; dropping deletes the data for good' },
  { re: /\bDROP\s+COLUMN\b/i, why: 'drops a column', instead: 'copy the data aside or rename the column; a dropped column cannot be recovered' },
  { re: /\bTRUNCATE\b/i, why: 'empties a table', instead: 'delete the rows you mean with a WHERE clause, after a backup' },
  // A table name is a bare or quoted identifier, optionally schema-qualified; what follows must end the statement.
  { re: /\bDELETE\s+FROM\s+(?:"[^"]+"|`[^`]+`|\w+)(?:\.(?:"[^"]+"|`[^`]+`|\w+))*\s*(?:;|$|\)|'|"|\n)/i, why: 'deletes every row in a table (no WHERE)', instead: 'add a WHERE clause, or back the table up first' },
  { re: /\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/i, why: 'switches row-level security off', instead: 'add the policy the app needs instead of removing the protection' },
  { re: /\bsupabase\s+db\s+reset\b/i, why: 'resets the Supabase database', instead: 'run the one migration you need, or reset a branch, not production' },
  { re: /\bprisma\s+(migrate\s+reset|db\s+push\s+--force-reset)\b/i, why: 'resets the database through Prisma', instead: 'create a migration for the change you need' },
  { re: /\bfirebase\s+firestore:delete\b.*(--all-collections|-r\b)/i, why: 'deletes Firestore collections', instead: 'delete the single document or collection you mean, after an export' },
  { re: /\brm\s+-rf\s+(\/|~|\.|\*)(\s|$)/, why: 'removes a whole directory tree', instead: 'name the files you mean' },
]
const SECRET_SHAPES = [/\b[sr]k_(live|test)_[0-9A-Za-z]{16,}\b/, /\bsb_secret_[0-9A-Za-z_-]{20,}\b/, /\bsk-ant-[0-9A-Za-z_-]{20,}\b/, /\bsk-(proj-)?[0-9A-Za-z_-]{32,}\b/, /\bAKIA[0-9A-Z]{16}\b/, /\bghp_[0-9A-Za-z]{30,}\b/, /\bre_[0-9A-Za-z]{20,}\b/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./]

// Programs that only read or search: a command segment that starts with one of these may mention the dangerous
// words (grep for them, print a migration, write a note) without running them.
const READ_ONLY = new Set(['grep', 'rg', 'ag', 'ack', 'cat', 'less', 'more', 'head', 'tail', 'sed', 'awk', 'find', 'ls', 'wc', 'diff', 'echo', 'printf', 'man', 'which', 'file', 'stat', 'bat', 'tee'])
const READ_ONLY_GIT = new Set(['log', 'diff', 'show', 'grep', 'blame', 'status', 'commit', 'add', 'stash', 'branch', 'tag'])

// Programs that execute what they are given: when one of these appears anywhere in the command, the whole
// command is judged, so `echo "..." | psql` and `grep ... | sh` are not excused by their read-only producer.
const EXECUTORS = new Set(['psql', 'mysql', 'mariadb', 'sqlite3', 'supabase', 'prisma', 'wrangler', 'turso', 'pgcli', 'sh', 'bash', 'zsh', 'fish', 'eval', 'xargs', 'node', 'python', 'python3', 'bun', 'deno', 'npx', 'pnpm', 'npm', 'yarn', 'ssh'])

/** Split on pipes, &&, || and ; (outside quotes) so each program is judged on its own. A heredoc body stays with its command. */
function segments(command) {
  const out = []
  let cur = ''
  let quote = null
  let heredoc = null
  for (let i = 0; i < command.length; i++) {
    const c = command[i]
    if (heredoc) {
      cur += c
      if (c === '\n') {
        const rest = command.slice(i + 1)
        const line = rest.slice(0, rest.indexOf('\n') === -1 ? rest.length : rest.indexOf('\n'))
        if (line.trim() === heredoc) {
          cur += line
          i += line.length
          heredoc = null
        }
      }
      continue
    }
    if (quote) {
      cur += c
      if (c === quote && command[i - 1] !== '\\') quote = null
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      cur += c
      continue
    }
    if (c === '|' || c === ';' || c === '&' || c === '\n') {
      const m = /<<-?\s*['"]?(\w+)['"]?\s*$/.exec(cur)
      if (c === '\n' && m) {
        heredoc = m[1]
        cur += c
        continue
      }
      if (cur.trim()) out.push(cur)
      cur = ''
      continue
    }
    cur += c
  }
  if (cur.trim()) out.push(cur)
  return out
}

function hasExecutor(segs) {
  return segs.some((s) => EXECUTORS.has(firstProgram(s).prog))
}

function firstProgram(segment) {
  const words = segment.trim().replace(/^(sudo|time|nice|env(\s+\w+=\S*)*)\s+/, '').split(/\s+/)
  const prog = (words[0] ?? '').replace(/^.*\//, '')
  return { prog, sub: words[1] ?? '' }
}

function isReadOnly(segment) {
  const { prog, sub } = firstProgram(segment)
  if (READ_ONLY.has(prog)) return true
  if (prog === 'git' && READ_ONLY_GIT.has(sub)) return true
  // A heredoc into a file (cat > notes.md <<EOF ...) is writing text, not running it.
  return /^\s*(cat|tee)\b/.test(segment)
}

function git(args, cwd) {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 })
  } catch {
    return ''
  }
}

/** The text a push would publish: what is staged plus every commit not yet on the upstream. */
function outgoingText(cwd) {
  let text = git(['diff', '--cached', '--no-color'], cwd)
  const upstream = git(['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}'], cwd).trim()
  const range = upstream ? `${upstream}..HEAD` : 'origin/HEAD..HEAD'
  text += git(['log', '-p', '--no-color', '--format=%H', range], cwd)
  // Only added lines are new; context and removed lines are already published (or being taken out).
  return text.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++')).join('\n')
}

let input = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (c) => (input += c))
process.stdin.on('end', () => {
  let command = ''
  let cwd = process.cwd()
  try {
    const parsed = JSON.parse(input)
    const raw = parsed.tool_input?.command ?? parsed.tool_input?.cmd ?? ''
    command = Array.isArray(raw) ? raw.join(' ') : String(raw)
    if (typeof parsed.cwd === 'string' && parsed.cwd) cwd = parsed.cwd
  } catch {
    process.exit(0)
  }
  const segs = segments(command)
  const judged = hasExecutor(segs) ? [command] : segs
  for (const seg of judged) {
    if (!hasExecutor(segs) && isReadOnly(seg)) continue
    for (const r of RULES) {
      if (r.re.test(seg)) {
        process.stderr.write(`Arbiter guard: this command ${r.why}. Safer: ${r.instead}. (Set ARBITER_GUARD=off to override.)\n`)
        process.exit(2)
      }
    }
  }
  if (/\bgit\s+push\b/.test(command)) {
    const hit = SECRET_SHAPES.find((s) => s.test(outgoingText(cwd)))
    if (hit) {
      process.stderr.write('Arbiter guard: the commits about to be pushed contain something shaped like a secret key. Move it to an environment variable and rewrite the commit before pushing. (Set ARBITER_GUARD=off to override.)\n')
      process.exit(2)
    }
  }
  process.exit(0)
})
