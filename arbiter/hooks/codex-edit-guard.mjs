// Arbiter edit guard for Codex: a PreToolUse hook on apply_patch, the tool Codex edits files with. It reads the
// patch, works out each file's text before and after, and runs the same judgement as the Claude Code hook
// (edit-rules.mjs). Codex hooks cannot ask the person directly, so a risky edit is denied with the reason and a
// code; the agent relays it, and the person sends a message of only `arbiter allow <code>` to let the retried edit through
// once (codex-allow.mjs records that). Deleting or renaming away auth middleware is judged too. ARBITER_EDIT_GUARD=off switches it off.
import { readFileSync, existsSync, appendFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, isAbsolute, relative } from 'node:path'
import { OFF, watched, judgeEdit, judgeRemoval, modelSkipped, readHookInput } from './edit-rules.mjs'
import { approvalCode, isApproved, consume } from './codex-approvals.mjs'

/** Splits an apply_patch body into file operations: { kind: add|update|delete, path, moveTo, lines }. */
function parsePatch(text) {
  const start = text.indexOf('*** Begin Patch')
  const end = text.lastIndexOf('*** End Patch')
  const body = text.slice(start < 0 ? 0 : start, end < 0 ? text.length : end).split('\n')
  const ops = []
  let cur = null
  for (const line of body) {
    const head = /^\*\*\* (Add|Update|Delete) File: (.+)$/.exec(line)
    if (head) {
      cur = { kind: head[1].toLowerCase(), path: head[2].trim(), moveTo: null, lines: [] }
      ops.push(cur)
      continue
    }
    const move = /^\*\*\* Move to: (.+)$/.exec(line)
    if (move && cur) { cur.moveTo = move[1].trim(); continue }
    if (line.startsWith('*** ')) continue // Begin Patch, End of File
    if (cur) cur.lines.push(line)
  }
  return ops
}

function findSeq(lines, seq, from) {
  const norms = [(s) => s, (s) => s.trimEnd(), (s) => s.trim()]
  for (const n of norms) {
    for (let i = from; i + seq.length <= lines.length; i++) {
      let ok = true
      for (let j = 0; j < seq.length && ok; j++) ok = n(lines[i + j]) === n(seq[j])
      if (ok) return i
    }
  }
  return -1
}

/** Applies an Update File section's hunks to the old text. A hunk that does not match adds its new lines at the end, so added text is still judged. */
function applyUpdate(before, patchLines) {
  const lines = before.split('\n')
  const hunks = []
  let h = null
  for (const l of patchLines) {
    if (l.startsWith('@@')) { h = { anchor: l.slice(2).trim(), old: [], new: [] }; hunks.push(h); continue }
    if (!h) { h = { anchor: '', old: [], new: [] }; hunks.push(h) }
    const tag = l[0]
    const rest = l.slice(1)
    if (tag === '-') h.old.push(rest)
    else if (tag === '+') h.new.push(rest)
    else { const ctx = tag === ' ' ? rest : l; h.old.push(ctx); h.new.push(ctx) }
  }
  let cursor = 0
  for (const hk of hunks) {
    // A trailing blank line in a hunk is usually the patch's own line break, not file content.
    while (hk.old.length && hk.new.length && hk.old.at(-1) === '' && hk.new.at(-1) === '') { hk.old.pop(); hk.new.pop() }
    if (hk.anchor) {
      const a = lines.findIndex((l, i) => i >= cursor && l.trim() === hk.anchor)
      if (a >= 0) cursor = a + 1
    }
    if (!hk.old.length) { lines.push(...hk.new); continue }
    const at = findSeq(lines, hk.old, cursor)
    if (at < 0) { lines.push(...hk.new); continue }
    lines.splice(at, hk.old.length, ...hk.new)
    cursor = at + hk.new.length
  }
  return lines.join('\n')
}

function debug(msg) {
  if (!process.env.ARBITER_DEBUG) return
  try { appendFileSync(join(process.env.ARBITER_STATE_DIR ?? join(homedir(), '.arbiter'), 'debug.log'), `${new Date().toISOString()} codex-edit-guard ${msg}\n`) } catch {}
}

const input = await readHookInput()
if (OFF || !input) process.exit(0)
const patch = String(input.tool_input?.command ?? input.tool_input?.input ?? input.tool_input?.patch ?? '')
const cwd = typeof input.cwd === 'string' && input.cwd ? input.cwd : process.cwd()
const session = String(input.session_id ?? '')
const abs = (p) => (isAbsolute(p) ? p : join(cwd, p))
const read = (p) => { try { return existsSync(abs(p)) ? readFileSync(abs(p), 'utf8') : '' } catch { return '' } }
const ops = parsePatch(patch)
if (!ops.length) {
  // An edit this guard cannot read is let through (a hook cannot do better than Codex's own patch parser), but not silently.
  process.stderr.write('Arbiter edit guard: could not read any file operations in this apply_patch call, so it was not checked.\n')
  debug(`no operations parsed; tool_input=${JSON.stringify(input.tool_input ?? null).slice(0, 4000)}`)
  process.exit(0)
}
const hits = []
for (const op of ops) {
  let file = op.path
  let reason = null
  let after = ''
  if (op.kind === 'delete') {
    if (!watched(op.path)) continue
    reason = judgeRemoval(abs(op.path), read(op.path))
  } else {
    file = op.moveTo ?? op.path
    if (!watched(file) && !watched(op.path)) continue
    const before = op.kind === 'update' ? read(op.path) : ''
    after = op.kind === 'add' ? op.lines.map((l) => (l.startsWith('+') ? l.slice(1) : l)).join('\n') : applyUpdate(before, op.lines)
    if (op.moveTo) reason = judgeRemoval(abs(op.path), before, abs(op.moveTo))
    if (!reason && watched(file)) reason = await judgeEdit(abs(file), before, after)
  }
  if (reason) hits.push({ file: relative(cwd, abs(file)) || file, reason, code: approvalCode(session, abs(file), reason, after) })
}
if (modelSkipped()) process.stderr.write(`Arbiter edit guard: the decision model ran out of time on ${modelSkipped()} question(s), so the rules judged those alone.\n`)
const paused = hits.filter((h) => !isApproved(session, h.code))
if (!paused.length) {
  // Every finding in this edit was allowed by the person: the edit goes ahead and uses those approvals up.
  if (hits.length) { try { consume(session, hits.map((h) => h.code)) } catch {} }
  process.exit(0)
}
const what = paused.map((p) => `${p.file}: ${p.reason} (code ${p.code})`).join(' ')
const codes = paused.map((p) => `arbiter allow ${p.code}`).join(', ')
const reason = `Arbiter paused this edit. ${what} Stop and ask the person whether to go ahead, explaining the risk in plain words. Do not make this change another way (shell commands, a different patch) to get around the check. If they want it, they send a message containing only \`${codes}\`, typed themselves; then you retry exactly the same edit. Each allow covers that one edit once. (Set ARBITER_EDIT_GUARD=off to stop these checks.)`
process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }))
process.exit(0)
