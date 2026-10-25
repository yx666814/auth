import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, type LoginPayload, type UserProfile } from '../api/client'

interface AuthState {
  user: UserProfile | null
  /** False until the provider knows whether there is a session. */
  ready: boolean
  login: (payload: LoginPayload) => Promise<void>
  logout: () => Promise<void>
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null)
  const [ready, setReady] = useState(false)

  // Tokens deliberately live in memory only (see api/client.ts), so a page
  // load normally starts anonymous. They can still be present when the
  // provider mounts after an in-app sign-in, so ask the API whose session
  // this is before the guards decide where to send the visitor.
  useEffect(() => {
    if (!api.accessToken) {
      setReady(true)
      return
    }
    let cancelled = false
    api
      .me()
      .then((profile) => {
        if (!cancelled) setUser(profile)
      })
      .catch(() => {
        if (!cancelled) setUser(null)
      })
      .finally(() => {
        if (!cancelled) setReady(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(
    () =>
      api.onTokensChanged((tokens) => {
        // A refresh rejected because the session was revoked elsewhere must
        // clear the cached profile, not just the tokens.
        if (!tokens) setUser(null)
      }),
    [],
  )

  const login = useCallback(async (payload: LoginPayload) => {
    await api.login(payload)
    setUser(await api.me())
  }, [])

  const logout = useCallback(async () => {
    await api.logout()
    setUser(null)
  }, [])

  const refreshUser = useCallback(async () => {
    if (!api.accessToken) {
      setUser(null)
      return
    }
    try {
      setUser(await api.me())
    } catch {
      setUser(null)
    }
  }, [])

  const value = useMemo<AuthState>(
    () => ({ user, ready, login, logout, refreshUser }),
    [user, ready, login, logout, refreshUser],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside <AuthProvider>')
  return context
}
