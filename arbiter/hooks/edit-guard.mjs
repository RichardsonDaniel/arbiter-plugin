// Arbiter edit guard for Claude Code: a PreToolUse hook on Edit, Write and MultiEdit. When an edit looks like it
// removes a sign-in check from a route, opens a database policy to everyone, or puts a secret in code that ships
// to the browser, it asks the person before the edit happens ("ask", never a silent block). Everything else passes
// untouched. The judgement lives in edit-rules.mjs, shared with the Codex entry point (codex-edit-guard.mjs).
// Set ARBITER_EDIT_GUARD=off to switch it off.
import { readFileSync, existsSync } from 'node:fs'
import { join, isAbsolute } from 'node:path'
import { OFF, watched, judgeEdit, readHookInput } from './edit-rules.mjs'

function apply(input, before) {
  const t = input.tool_input ?? {}
  if (typeof t.content === 'string') return t.content
  const edits = Array.isArray(t.edits) ? t.edits : [{ old_string: t.old_string, new_string: t.new_string, replace_all: t.replace_all }]
  let after = before
  for (const e of edits) {
    if (typeof e.old_string !== 'string' || typeof e.new_string !== 'string') continue
    after = e.replace_all ? after.split(e.old_string).join(e.new_string) : after.replace(e.old_string, e.new_string)
  }
  return after
}

const input = await readHookInput()
if (OFF || !input) process.exit(0)
const file = String(input.tool_input?.file_path ?? '')
if (!file || !watched(file)) process.exit(0)
const abs = isAbsolute(file) ? file : join(input.cwd ?? process.cwd(), file)
let before = ''
try { if (existsSync(abs)) before = readFileSync(abs, 'utf8') } catch { process.exit(0) }
const reason = await judgeEdit(abs, before, apply(input, before))
if (reason) process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: `Arbiter: ${reason} Allow this edit? (Set ARBITER_EDIT_GUARD=off to stop these checks.)` } }))
process.exit(0)
