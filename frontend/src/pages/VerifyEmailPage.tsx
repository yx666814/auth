import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ApiError, api } from '../api/client'

type State = 'verifying' | 'done' | 'failed'

export function VerifyEmailPage() {
  const [params] = useSearchParams()
  const token = params.get('token')
  const userId = params.get('user_id')
  const [state, setState] = useState<State>('verifying')
  const [message, setMessage] = useState('')
  const started = useRef(false)

  useEffect(() => {
    if (!token || !userId) {
      setState('failed')
      setMessage('This verification link is incomplete.')
      return
    }
    // React 18 StrictMode mounts effects twice in development; the token is
    // single use, so a second request would report a false failure.
    if (started.current) return
    started.current = true

    api
      .verifyEmail(token, userId)
      .then(() => setState('done'))
      .catch((error: unknown) => {
        setState('failed')
        setMessage(
          error instanceof ApiError && error.status === 400
            ? 'This link is invalid or has expired.'
            : 'Verification could not be completed.',
        )
      })
  }, [token, userId])

  return (
    <main className="card">
      <h1>Email verification</h1>
      {state === 'verifying' ? <p role="status">Verifying your address…</p> : null}
      {state === 'done' ? (
        <>
          <p className="notice" role="status">
            Your email address is verified.
          </p>
          <p>
            <Link to="/login">Sign in</Link>
          </p>
        </>
      ) : null}
      {state === 'failed' ? (
        <>
          <p className="form-error" role="alert">
            {message}
          </p>
          <p className="muted">Request a new link by signing in and trying again, or contact your administrator.</p>
        </>
      ) : null}
    </main>
  )
}
