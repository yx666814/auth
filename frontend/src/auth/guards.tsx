import { Navigate, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAuth } from './AuthProvider'

/** Sends anonymous visitors to /login, remembering where they were headed. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, ready } = useAuth()
  const location = useLocation()

  // Wait for the profile lookup before deciding: redirecting first would
  // bounce a signed-in visitor to /login on every reload.
  if (!ready) return null
  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />
  }
  return <>{children}</>
}

/** Signed-in visitors have no reason to see login/register. */
export function RedirectIfAuthed({ children }: { children: ReactNode }) {
  const { user, ready } = useAuth()
  if (!ready) return null
  if (user) return <Navigate to="/account" replace />
  return <>{children}</>
}
