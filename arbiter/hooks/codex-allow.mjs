// Arbiter for Codex: a UserPromptSubmit hook. When the person sends a message made only of `arbiter allow <code>`
// lines after the edit guard paused an edit, it records the approval so that same edit goes through once when the
// agent retries it. An allow line inside a longer message (for example a quoted pause message) does not count.
import { readHookInput } from './edit-rules.mjs'
import { allowCodes, approve } from './codex-approvals.mjs'

const input = await readHookInput()
const codes = allowCodes(String(input?.prompt ?? ''))
if (codes.length && input?.session_id) {
  try {
    approve(String(input.session_id), codes)
    process.stdout.write(`Arbiter: the person allowed the paused edit (${codes.join(', ')}), once. Retry that same edit now, unchanged.\n`)
  } catch {
    // An approval that cannot be saved leaves the edit paused, which is the safe direction.
  }
}
process.exit(0)
