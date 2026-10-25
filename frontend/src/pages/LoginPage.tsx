import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { ApiError, type CaptchaChallenge } from '../api/client'
import { CaptchaField } from '../components/CaptchaField'
import { useAuth } from '../auth/AuthProvider'
import { deviceLabel } from '../lib/device'

interface LocationState {
  from?: string
  notice?: string
}

export function LoginPage() {
  const { user, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const state = (location.state ?? {}) as LocationState

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [captcha, setCaptcha] = useState('')
  const [challenge, setChallenge] = useState<CaptchaChallenge | null>(null)
  const [captchaReload, setCaptchaReload] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  if (user) return <Navigate to="/account" replace />

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (!challenge) return
    setSubmitting(true)
    setError(null)
    try {
      await login({
        email,
        password,
        captcha_token: challenge.token,
        captcha_value: captcha,
        device_id: deviceLabel().id,
        device_name: deviceLabel().name,
      })
      navigate(state.from ?? '/account', { replace: true })
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
      <h1>Sign in</h1>
      {state.notice ? <p className="notice">{state.notice}</p> : null}
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
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            disabled={submitting}
          />
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
        <button type="submit" disabled={submitting || !challenge}>
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
      <p className="muted">
        No account? <a href="/register">Create one</a>
      </p>
    </main>
  )
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 423) return 'This account is temporarily locked. Try again later.'
    if (error.status === 429) return 'Too many attempts. Wait a minute and try again.'
    if (error.status === 401) return 'Invalid email, password, or verification code.'
    return error.message
  }
  return 'Something went wrong. Please try again.'
}
