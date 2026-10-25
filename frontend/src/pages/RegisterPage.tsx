import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError, api, type CaptchaChallenge } from '../api/client'
import { CaptchaField } from '../components/CaptchaField'

export function RegisterPage() {
  const navigate = useNavigate()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [captcha, setCaptcha] = useState('')
  const [challenge, setChallenge] = useState<CaptchaChallenge | null>(null)
  const [captchaReload, setCaptchaReload] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const policy = password.length > 0 ? passwordProblem(password) : null
  const mismatch = confirm.length > 0 && confirm !== password

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (!challenge || policy || mismatch) return
    setSubmitting(true)
    setError(null)
    try {
      const result = await api.register({
        email,
        password,
        captcha_token: challenge.token,
        captcha_value: captcha,
      })
      navigate('/login', {
        replace: true,
        state: { notice: `Account created for ${result.email}. Check your inbox to verify it.` },
      })
    } catch (err) {
      setCaptcha('')
      setCaptchaReload((n) => n + 1)
      setError(messageFor(err))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="card">
      <h1>Create account</h1>
      <form onSubmit={handleSubmit} noValidate>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            disabled={submitting}
          />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            autoComplete="new-password"
            required
            minLength={12}
            maxLength={128}
            aria-describedby="password-help"
            aria-invalid={Boolean(policy)}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            disabled={submitting}
          />
          <p id="password-help" className={policy ? 'field-error' : 'muted'}>
            {policy ?? 'At least 12 characters with upper-case, lower-case, number, and symbol.'}
          </p>
        </div>
        <div className="field">
          <label htmlFor="confirm">Confirm password</label>
          <input
            id="confirm"
            type="password"
            autoComplete="new-password"
            required
            aria-invalid={mismatch}
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            disabled={submitting}
          />
          {mismatch ? <p className="field-error">Passwords do not match.</p> : null}
        </div>
        <CaptchaField
          value={captcha}
          onChange={setCaptcha}
          onChallenge={setChallenge}
          reloadKey={captchaReload}
          disabled={submitting}
        />
        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" disabled={submitting || !challenge || Boolean(policy) || mismatch}>
          {submitting ? 'Creating…' : 'Create account'}
        </button>
      </form>
      <p className="muted">
        Already registered? <Link to="/login">Sign in</Link>
      </p>
    </main>
  )
}

/**
 * Mirrors the server policy (backend/app/schemas/auth.py) for instant feedback.
 * The server remains the authority; this only saves a round trip on typos.
 */
export function passwordProblem(password: string): string | null {
  if (password.length < 12) return 'Use at least 12 characters.'
  if (!/[a-z]/.test(password)) return 'Include a lower-case letter.'
  if (!/[A-Z]/.test(password)) return 'Include an upper-case letter.'
  if (!/[0-9]/.test(password)) return 'Include a number.'
  if (!/[^A-Za-z0-9]/.test(password)) return 'Include a symbol.'
  for (let index = 0; index + 2 < password.length; index += 1) {
    if (password[index] === password[index + 1] && password[index] === password[index + 2]) {
      return 'Avoid repeating the same character three times.'
    }
  }
  return null
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    // 400 covers both a wrong captcha and an already-registered email; the
    // server keeps those indistinguishable on purpose.
    if (error.status === 400) return 'Unable to register this email address. Try a new verification code.'
    if (error.status === 429) return 'Too many attempts. Wait a minute and try again.'
    return error.message
  }
  return 'Something went wrong. Please try again.'
}
