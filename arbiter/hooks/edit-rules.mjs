// Arbiter edit rules: the judgement shared by the edit-guard hook entry points for each coding tool
// (edit-guard.mjs for Claude Code's Edit, Write and MultiEdit; codex-edit-guard.mjs for Codex's apply_patch).
// Given a file's text before and after an edit, judgeEdit returns the reason to ask the person, or null when the
// edit can go ahead. Most edits are skipped by a cheap pre-filter before any analysis.
//
// If a local decision model is running (ARBITER_LAYA_URL or LAYA_URL, see product/docs/decision-models.md), its
// answer confirms or clears what the rules suspect; without one, the rules decide alone. Code never leaves the
// machine. Set ARBITER_EDIT_GUARD=off to switch the edit guards off.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

export const OFF = /^(off|0|false|no)$/i.test(process.env.ARBITER_EDIT_GUARD ?? '')
const LAYA = process.env.ARBITER_LAYA_URL ?? process.env.LAYA_URL ?? ''
// Per-model clearing thresholds (product/packages/decide/src/index.ts); an unknown model never clears.
const CLEAR_BY_MODEL = { 'arbiter-v4': { route_guarded: 0.97, policy_scope: 0.98 }, 'arbiter-v5': { route_guarded: 0.9, policy_scope: 0.93 }, 'arbiter-v6': { route_guarded: 0.9, policy_scope: 0.94 }, 'arbiter-v7': { route_guarded: 0.96, policy_scope: 0.98 } }
// Probability at or above which a model's before-guarded, after-open judgement asks (per model, measured with
// corpus/decisions/eval_edit_guard.py). ARBITER_ASK_P overrides it for measurement.
const ASK_BY_MODEL = { 'arbiter-v4': 0.8, 'arbiter-v5': 0.95, 'arbiter-v6': 0.8, 'arbiter-v7': 0.8 }
const askP = (m) => Number(process.env.ARBITER_ASK_P ?? ASK_BY_MODEL[m?.model] ?? 0.8)
const clear = (m, q) => CLEAR_BY_MODEL[m?.model]?.[q] ?? 1.01

const CODE = /\.(ts|tsx|js|jsx|mjs|cjs|py|rb|php|go|sql|svelte|vue|astro)$/i
const ENVFILE = /(^|\/)\.env(\.[\w-]+)?$/
const ROUTE_PATH = /(^|\/)(app\/(.+\/)?route\.[jt]sx?$|pages\/api\/|src\/pages\/api\/|supabase\/functions\/|functions\/|api\/|routes?\/|server\/|controllers?\/|app\/Http\/Controllers\/|views\.py$|urls\.py$|.*actions?\.[jt]sx?$)/i
const MIGRATION = /(\.sql$|(^|\/)supabase\/migrations\/|(^|\/)migrations?\/)/i
const SERVER_ONLY = /(^|\/)(app\/(.+\/)?route\.[jt]sx?$|pages\/api\/|src\/pages\/api\/|supabase\/functions\/|server\/|api\/|routes?\/|scripts?\/|.*\.server\.[jt]sx?$|middleware\.[jt]s$|.*\.(py|rb|php|go|sql)$)/i
const CLIENT_HINT = /(^|\/)(src\/|app\/|components\/|pages\/|public\/|lib\/|hooks\/)/i

// A handler is guarded when it calls a helper that rejects on its own (requireUser, withAuth, auth middleware,
// a decorator or permission class), or when it reads the caller and also rejects (401/403, Unauthorized, throw).
const HELPER = /\brequire(Auth|User|Session|Admin|Login|Role|Owner)\w*\(|\bwithAuth\b|\bensure(LoggedIn|Auth|User)\w*\b|auth\.protect\(|passport\.authenticate\(|\bauthenticate(d|User)?\b\s*[,)]|auth:sanctum|auth:api|->middleware\(\s*\[?\s*['"]auth|\$this->authorize\(|Gate::(authorize|denies)|@login_required|LoginRequiredMixin|IsAuthenticated|before_action\s+:authenticate|verify(Token|Jwt|JWT|Session|Signature|Webhook)\w*\(|constructEvent\(|timingSafeEqual\(/
const CHECK = /\b(get|require|verify|check|validate|fetch|load|ensure|read|current)\w*(User|Auth|Session|Token|Claims|Caller|Member|Owner|Admin|Principal|Identity)\w*\s*\(|(!==?|===?)\s*(process\.env\.|Deno\.env\.get\(|env\.)?[A-Z][A-Z0-9_]{3,}\b|\.auth\.getUser\(|\.auth\.getClaims\(|\.auth\.getSession\(|\bauth\(\)|getServerSession\(|\bcurrentUser\(|getToken\(|getAuth\(|headers\.get\(['"](authorization|x-[\w-]*(secret|key|token))['"]\)|req\.headers\[?['".]?(authorization|x-)|req\.user\b|session\??\.user|Auth::(check|user|id)\(|request\.user/i
const REJECT = /status:\s*40[13]\b|status\(40[13]\)|\b40[13]\b|Unauthori[sz]ed|Forbidden|throw new \w*(Auth|Unauthori[sz]ed|Forbidden)\w*|abort\(40[13]|redirect\(['"`][^'"`]*(login|sign-?in)/i
const MUTATE = /\.(delete|update|upsert|insert|destroy|remove)\s*\(|\b(deleteMany|updateMany|createMany)\b|\bDELETE\s+FROM\b|\bUPDATE\s+\w+\s+SET\b|\bINSERT\s+INTO\b/i
/** The data change happens before the first check of the caller (the check runs too late to stop it). */
function lateCheck(text) {
  const m = text.search(MUTATE)
  const c = Math.min(...[text.search(CHECK), text.search(HELPER)].filter((i) => i >= 0))
  return m >= 0 && Number.isFinite(c) && m < c
}
function guarded(text) {
  return HELPER.test(text) || (CHECK.test(text) && REJECT.test(text))
}

const SECRET_SHAPES = [/\b[sr]k_live_[0-9A-Za-z]{16,}\b/, /\bsb_secret_[0-9A-Za-z_-]{20,}\b/, /\bsk-ant-[0-9A-Za-z_-]{20,}\b/, /\bsk-(proj-)?[0-9A-Za-z_-]{32,}\b/, /\bAKIA[0-9A-Z]{16}\b/, /\bghp_[0-9A-Za-z]{30,}\b/, /\bre_[0-9A-Za-z]{20,}\b/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/]
const SERVICE_ROLE = /SUPABASE_SERVICE_ROLE_KEY|service_role|SUPABASE_SECRET_KEY|sb_secret_/
const PUBLIC_ENV = /^(NEXT_PUBLIC_|VITE_|PUBLIC_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_)\w*(SECRET|SERVICE_ROLE|PRIVATE|_KEY)\w*\s*=/m

const POLICY = /create\s+policy[\s\S]*?;/gi
const OPEN_COND = /using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)|auth\.role\(\)\s*=\s*'authenticated'|auth\.uid\(\)\s+is\s+not\s+null|user_metadata/i

// The whole hook must finish inside the tool's hook timeout (5 seconds in both plugins). Model questions stop
// once the budget is spent and the rules judge alone; modelSkipped() lets the entry point say so.
const BUDGET_MS = Number(process.env.ARBITER_HOOK_BUDGET_MS ?? 4000)
const deadline = Date.now() + BUDGET_MS
let skipped = 0
export const modelSkipped = () => skipped

async function ask(state, qid, question) {
  if (!LAYA) return null
  const left = deadline - Date.now()
  if (left < 200) { skipped++; return null }
  try {
    const ctl = AbortSignal.timeout(Math.min(1500, left - 100))
    const res = await fetch(LAYA.replace(/\/$/, '') + '/v1/systemone', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ state: state.slice(0, 6000), questions: { [qid]: question } }), signal: ctl })
    if (!res.ok) return null
    const body = await res.json()
    const a = body.answers?.[qid]
    const model = String(body.model ?? '')
    return a && typeof a.choice === 'string' ? { model, choice: a.choice, score: Number(a.score ?? a.confidence ?? 0), p: Number(a.answer_confidence ?? a.probabilities?.[a.choice] ?? 0) } : null
  } catch {
    return null
  }
}

// A copy of corpus/decisions/questions.json ships with the plugin; the wording must match what the model was trained on.
let questionsCache
function loadQuestions() {
  if (questionsCache !== undefined) return questionsCache
  try { questionsCache = JSON.parse(readFileSync(join(new URL('.', import.meta.url).pathname, 'questions.json'), 'utf8')) } catch { questionsCache = null }
  return questionsCache
}

/** True when the edit guard looks at this path at all (code files and .env files). */
export function watched(path) {
  return CODE.test(path) || ENVFILE.test(path)
}

/**
 * The reason to ask the person before this edit, or null to let it through.
 * `path` is the file's absolute path (or one relative to the project), `before` is '' for a new file.
 */
export async function judgeEdit(path, before, after) {
  if (OFF || !watched(path)) return null
  if (before.length > 400_000 || after === before) return null
  const rel = path.replace(/\\/g, '/')
  const added = after.split('\n').filter((l) => !before.includes(l)).join('\n')
  const questions = loadQuestions()

  // 1. Secrets in code that reaches the browser, or exposed through a public env prefix.
  if (ENVFILE.test(rel) && PUBLIC_ENV.test(added)) return 'this puts a secret behind a public prefix (NEXT_PUBLIC_, VITE_ and similar), so it is bundled into the app every visitor downloads. Keep secrets unprefixed and use them only on the server.'
  const client = !SERVER_ONLY.test(rel) && (CLIENT_HINT.test(rel) || /['"]use client['"]/.test(after))
  if (client && !ENVFILE.test(rel)) {
    if (SECRET_SHAPES.some((re) => re.test(added))) return 'this adds a secret key to code that runs in the browser, where anyone can read it. Put it in a server-side environment variable instead.'
    if (SERVICE_ROLE.test(added)) return 'this uses the Supabase service-role key in code that runs in the browser. That key bypasses every database rule; use it only in server code.'
  }

  // 2. Database policies that let everyone in.
  if (MIGRATION.test(rel) || /\.sql$/i.test(rel)) {
    if (/disable\s+row\s+level\s+security/i.test(added)) return 'this switches row-level security off for a table, so any request with the public key can read and change every row.'
    const fresh = (after.match(POLICY) ?? []).filter((p) => !before.includes(p))
    for (const p of fresh) {
      const m = questions ? await ask(p, 'policy_scope', questions['policy-owner-scoped']) : null
      if (m && m.choice !== 'open' && m.score >= clear(m, 'policy_scope')) continue
      if ((m && m.choice === 'open') || OPEN_COND.test(p)) return `this adds a database policy that lets everyone (or every signed-in user) reach the rows: ${p.replace(/\s+/g, ' ').slice(0, 140)}`
    }
    if (/grant\s+[\w\s,]*\bon\b[\s\S]*?\bto\s+anon\b/i.test(added)) return 'this grants the anonymous role access to a table, so visitors who are not signed in can use it.'
  }

  // 3. A sign-in check removed from a route handler.
  if (ROUTE_PATH.test(rel) || /Deno\.serve\(|export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b|['"]use server['"]|\b(app|router)\.(get|post|put|patch|delete)\(/.test(after)) {
    const q = questions?.['route-guarded']
    const where = rel.split('/').slice(-3).join('/')
    // With the model running, it is the main judge: it asks when the handler was guarded before and is open after.
    if (before && q && LAYA) {
      const [mb, ma] = await Promise.all([ask(before, 'route_guarded', q), ask(after, 'route_guarded', q)])
      if (mb && ma) {
        if (mb.choice === 'guarded' && mb.p >= askP(mb) && ma.choice === 'unguarded' && ma.p >= askP(ma)) return `after this edit, ${where} no longer stops callers who are not signed in (or lack the required secret) before it reads or changes data.`
        if (!(guarded(before) && !guarded(after))) return null
      }
    }
    if (before && guarded(before) && !guarded(after)) {
      const m = q ? await ask(after, 'route_guarded', q) : null
      if (m && m.choice === 'guarded' && m.score >= clear(m, 'route_guarded')) return null
      return `this edit removes a sign-in or permission check from ${where}, which reads or changes data. Without it, anyone could call this route.`
    }
    // The rules still see a check, but it may now run too late or never reject. Only the model can judge that,
    // so this path needs it, and it asks only when the model is confident the handler is now open.
    if (before && guarded(before) && !lateCheck(before) && lateCheck(after)) return `after this edit, ${where} changes data before it checks who is calling, so the check comes too late to stop anyone.`
    if (before && guarded(before) && q) {
      // Asking is the safe direction, so this uses the answer's probability rather than the stricter calibrated confidence.
      const m = await ask(after, 'route_guarded', q)
      if (m && m.choice === 'unguarded' && m.p >= askP(m)) return `after this edit, the sign-in check in ${where} no longer protects the data: it runs too late, or never turns the caller away.`
    }
  }
  return null
}

// Next.js middleware (proxy.ts from Next 16) and auth middleware modules guard many routes at once.
const MIDDLEWARE = /(^|\/)((middleware|proxy)\.[jt]s|middlewares?\/[^/]*auth[^/]*\.[jt]s)$/i

/**
 * The reason to ask before a file is deleted or renamed away, or null. Removing a route file removes the route,
 * which is not a risk; removing middleware that checks the caller leaves every route it covered open.
 */
export function judgeRemoval(path, before, newPath = null) {
  if (OFF) return null
  const rel = path.replace(/\\/g, '/')
  if (!MIDDLEWARE.test(rel) || (newPath && MIDDLEWARE.test(newPath.replace(/\\/g, '/')))) return null
  if (!(guarded(before) || CHECK.test(before))) return null
  const where = rel.split('/').slice(-2).join('/')
  return `this ${newPath ? 'renames' : 'deletes'} ${where}, which checks who is calling before requests reach the app's routes. Without it, those routes may be open to anyone.`
}

/** Reads a hook's JSON input from stdin; resolves to null when it is not JSON. */
export function readHookInput() {
  return new Promise((resolve) => {
    let raw = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (c) => (raw += c))
    process.stdin.on('end', () => {
      try { resolve(JSON.parse(raw)) } catch { resolve(null) }
    })
  })
}
