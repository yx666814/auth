import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../src/api/client'
import { AuthProvider, useAuth } from '../src/auth/AuthProvider'
import { LoginPage } from '../src/pages/LoginPage'
import { captchaResponse, jsonResponse } from './helpers'

function renderLogin() {
  return render(
    <MemoryRouter initialEntries={['/login']}>
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    </MemoryRouter>,
  )
}

const profile = {
  id: 'u1',
  email: 'a@b.co',
  email_verified: true,
  is_active: true,
  roles: ['user'],
  created_at: '2024-01-01T00:00:00Z',
}

describe('LoginPage', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    api.setTokens(null)
    vi.unstubAllGlobals()
  })

  it('submits the captcha pair returned by the API', async () => {
    fetchMock.mockImplementation(async (url: string) => {
      const path = String(url)
      if (path.endsWith('/auth/captcha')) return captchaResponse()
      if (path.endsWith('/auth/login')) {
        return jsonResponse({
          access_token: 'access',
          refresh_token: 'refresh',
          token_type: 'bearer',
          user: { id: 'u1', email: 'a@b.co', email_verified: true, roles: ['user'] },
        })
      }
      if (path.endsWith('/users/me')) return jsonResponse(profile)
      throw new Error(`unexpected request: ${path}`)
    })

    const user = userEvent.setup()
    renderLogin()

    await user.type(screen.getByLabelText('Email'), 'a@b.co')
    await user.type(screen.getByLabelText('Password'), 'correct horse battery')
    await user.type(await screen.findByLabelText('Verification code'), 'ABC123')

    const submit = screen.getByRole('button', { name: 'Sign in' })
    await waitFor(() => expect(submit).toBeEnabled())
    await user.click(submit)

    await waitFor(() => expect(api.accessToken).toBe('access'))
    const loginCall = fetchMock.mock.calls.find(([url]) => String(url).endsWith('/auth/login'))
    expect(loginCall).toBeDefined()
    const body = JSON.parse((loginCall?.[1] as RequestInit).body as string)
    expect(body.captcha_token).toBe('c'.repeat(32))
    expect(body.captcha_value).toBe('ABC123')
  })

  it('explains a locked account and fetches a new captcha', async () => {
    let captchaCalls = 0
    fetchMock.mockImplementation(async (url: string) => {
      const path = String(url)
      if (path.endsWith('/auth/captcha')) {
        captchaCalls += 1
        return captchaResponse()
      }
      if (path.endsWith('/auth/login')) {
        return jsonResponse({ detail: 'Account is temporarily locked' }, 423)
      }
      throw new Error(`unexpected request: ${path}`)
    })

    const user = userEvent.setup()
    renderLogin()

    await user.type(screen.getByLabelText('Email'), 'a@b.co')
    await user.type(screen.getByLabelText('Password'), 'wrong')
    await user.type(await screen.findByLabelText('Verification code'), 'ABC123')
    const submit = screen.getByRole('button', { name: 'Sign in' })
    await waitFor(() => expect(submit).toBeEnabled())
    await user.click(submit)

    expect(await screen.findByRole('alert')).toHaveTextContent('temporarily locked')
    await waitFor(() => expect(captchaCalls).toBe(2))
  })
})

// Kept to make sure the provider hook is usable from tests too.
export function AuthProbe() {
  const { user } = useAuth()
  return <span>{user?.email ?? 'anonymous'}</span>
}
