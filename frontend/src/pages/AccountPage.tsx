import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthProvider'

export function AccountPage() {
  const { user, logout, refreshUser } = useAuth()
  const navigate = useNavigate()
  const [busy, setBusy] = useState(false)

  // The profile is cached from sign-in; another session may have changed or
  // revoked this account since, so re-read it when the tab regains focus.
  useEffect(() => {
    function onFocus() {
      void refreshUser()
    }
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [refreshUser])

  async function handleLogout() {
    setBusy(true)
    try {
      await logout()
    } finally {
      // logout() clears local tokens even when the server call fails, so the
      // user always ends up signed out here.
      setBusy(false)
      navigate('/login', { replace: true, state: { notice: 'You have been signed out.' } })
    }
  }

  if (!user) return null

  return (
    <main className="card">
      <h1>Your account</h1>
      <dl className="details">
        <dt>Email</dt>
        <dd>{user.email}</dd>
        <dt>Email verified</dt>
        <dd>{user.email_verified ? 'Yes' : 'Not yet'}</dd>
        <dt>Status</dt>
        <dd>{user.is_active ? 'Active' : 'Disabled'}</dd>
        <dt>Member since</dt>
        <dd>{new Date(user.created_at).toLocaleDateString()}</dd>
      </dl>
      {!user.email_verified ? (
        <p className="notice">
          Check your inbox for the verification link. Verified addresses are required for account recovery.
        </p>
      ) : null}
      <button type="button" onClick={handleLogout} disabled={busy}>
        {busy ? 'Signing out…' : 'Sign out'}
      </button>
    </main>
  )
}
