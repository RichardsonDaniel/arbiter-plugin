// Arbiter for Codex: a UserPromptSubmit hook. When the person types `arbiter allow <code>` after the edit guard
// paused an edit, it records the approval so the same edit goes through when the agent retries it.
import { readHookInput } from './edit-rules.mjs'
import { ALLOW_RE, approve } from './codex-approvals.mjs'

const input = await readHookInput()
const prompt = String(input?.prompt ?? '')
const codes = [...prompt.matchAll(ALLOW_RE)].map((m) => m[1].toLowerCase())
if (codes.length && input?.session_id) {
  try {
    approve(String(input.session_id), codes)
    process.stdout.write(`Arbiter: the person allowed the paused edit (${codes.join(', ')}). Retry that same edit now.\n`)
  } catch {
    // An approval that cannot be saved leaves the edit paused, which is the safe direction.
  }
}
process.exit(0)
