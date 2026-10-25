import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiClient, ApiError } from '../src/api/client'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function tokens(n: number) {
  return { access_token: `access-${n}`, refresh_token: `refresh-${n}`, token_type: 'bearer' }
}

describe('ApiClient', () => {
  let client: ApiClient

  beforeEach(() => {
    client = new ApiClient('/api')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('stores the token pair returned by login', async () => {
    const fetchMock = vi.fn(async () =>
      json({ ...tokens(1), user: { id: 'u1', email: 'a@b.co', email_verified: false } }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await client.login({ email: 'a@b.co', password: 'x', captcha_token: 't', captcha_value: 'v' })

    expect(client.accessToken).toBe('access-1')
    expect(client.refreshToken).toBe('refresh-1')
  })

  it('rotates the refresh token only once for concurrent 401s', async () => {
    client.setTokens(tokens(0))
    let refreshCalls = 0

    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith('/auth/refresh')) {
        refreshCalls += 1
        return json(tokens(1))
      }
      const authorization = (init?.headers as Record<string, string> | undefined)?.Authorization
      if (authorization === 'Bearer access-1') return json({ id: 'u1' })
      return json({ detail: 'Invalid access token' }, 401)
    })
    vi.stubGlobal('fetch', fetchMock)

    const [first, second] = await Promise.all([client.me(), client.me()])

    expect(first.id).toBe('u1')
    expect(second.id).toBe('u1')
    expect(refreshCalls).toBe(1)
  })

  it('clears the session when the refresh token is rejected', async () => {
    client.setTokens(tokens(0))
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json({ detail: 'Invalid refresh token' }, 401)),
    )

    await expect(client.me()).rejects.toBeInstanceOf(ApiError)
    expect(client.accessToken).toBeNull()
    expect(client.refreshToken).toBeNull()
  })

  it('notifies subscribers when the session ends', async () => {
    client.setTokens(tokens(0))
    const seen: Array<unknown> = []
    client.onTokensChanged((pair) => seen.push(pair))
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json({ detail: 'Invalid refresh token' }, 401)),
    )

    await client.me().catch(() => undefined)

    expect(seen).toEqual([null])
  })

  it('turns FastAPI validation errors into readable text', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => json({ detail: [{ loc: ['body'], msg: 'Password is too common' }] }, 422)),
    )

    const error = await client
      .register({ email: 'a@b.co', password: 'x', captcha_token: 't', captcha_value: 'v' })
      .catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).message).toBe('Password is too common')
    expect((error as ApiError).status).toBe(422)
  })

  it('does not retry logout when the access token is already invalid', async () => {
    client.setTokens(tokens(0))
    let refreshCalls = 0
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (String(url).endsWith('/auth/refresh')) refreshCalls += 1
        return json({ detail: 'Invalid access token' }, 401)
      }),
    )

    await expect(client.logout()).rejects.toBeInstanceOf(ApiError)
    expect(refreshCalls).toBe(0)
    expect(client.accessToken).toBeNull()
  })
})
