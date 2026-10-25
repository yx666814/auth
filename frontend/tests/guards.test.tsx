import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { render, screen, waitFor } from '@testing-library/react'
import { api } from '../src/api/client'
import { AuthProvider } from '../src/auth/AuthProvider'
import { RedirectIfAuthed, RequireAuth } from '../src/auth/guards'
import { AccountPage } from '../src/pages/AccountPage'

const profile = {
  id: 'u1',
  email: 'a@b.co',
  email_verified: true,
  is_active: true,
  created_at: '2024-01-01T00:00:00Z',
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function renderApp(initialEntry: string) {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <AuthProvider>
        <Routes>
          <Route
            path="/account"
            element={
              <RequireAuth>
                <AccountPage />
              </RequireAuth>
            }
          />
          <Route
            path="/login"
            element={
              <RedirectIfAuthed>
                <p>sign-in form</p>
              </RedirectIfAuthed>
            }
          />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('route guards', () => {
  beforeEach(() => {
    api.setTokens(null)
  })

  afterEach(() => {
    api.setTokens(null)
    vi.unstubAllGlobals()
  })

  it('redirects anonymous visitors away from a protected page', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json({ detail: 'Authentication required' }, 401)),
    )

    renderApp('/account')

    expect(await screen.findByText('sign-in form')).toBeDefined()
    expect(screen.queryByRole('heading', { name: 'Your account' })).toBeNull()
  })

  it('renders the protected page for a signed-in user', async () => {
    api.setTokens({ access_token: 'a', refresh_token: 'r', token_type: 'bearer' })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(profile)),
    )

    renderApp('/account')

    // The guard only knows the user after the provider loads /users/me.
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Your account' })).toBeDefined())
    expect(screen.getByText('a@b.co')).toBeDefined()
  })

  it('keeps a signed-in user off the sign-in page', async () => {
    api.setTokens({ access_token: 'a', refresh_token: 'r', token_type: 'bearer' })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json(profile)),
    )

    renderApp('/login')

    expect(await screen.findByRole('heading', { name: 'Your account' })).toBeDefined()
    expect(screen.queryByText('sign-in form')).toBeNull()
  })
})
