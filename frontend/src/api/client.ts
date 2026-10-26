/**
 * Thin HTTP client for the backend API.
 *
 * Access tokens are short lived (15 minutes by default) and the refresh token
 * is single-use: the server rotates it on every call. That means two parallel
 * refreshes would race and one of them would look like token reuse, which the
 * backend treats as a compromise signal and revokes every session. Every
 * refresh therefore goes through one in-flight promise.
 */

const API_BASE = '/api'

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export interface TokenPair {
  access_token: string
  refresh_token: string
  token_type: string
}

export interface UserProfile {
  id: string
  email: string
  email_verified: boolean
  is_active: boolean
  /** Snapshot from the account row; drives client-side gating only. */
  roles: string[]
  created_at: string
}

export interface LoginResult extends TokenPair {
  user: { id: string; email: string; email_verified: boolean; roles: string[] }
}

export interface CaptchaChallenge {
  token: string
  /** A ready-to-use `data:image/png;base64,...` URL. */
  image: string
}

export interface RegisterPayload {
  email: string
  password: string
  captcha_token: string
  captcha_value: string
}

export interface LoginPayload {
  email: string
  password: string
  captcha_token: string
  captcha_value: string
  device_id?: string
  device_name?: string
}

type Listener = (tokens: TokenPair | null) => void

export class ApiClient {
  private tokens: TokenPair | null = null
  private refreshInFlight: Promise<TokenPair | null> | null = null
  private readonly listeners = new Set<Listener>()

  constructor(private readonly base = API_BASE) {}

  get accessToken(): string | null {
    return this.tokens?.access_token ?? null
  }

  get refreshToken(): string | null {
    return this.tokens?.refresh_token ?? null
  }

  /** Subscribe to token changes (login, refresh, logout). Returns unsubscribe. */
  onTokensChanged(listener: Listener): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  setTokens(tokens: TokenPair | null): void {
    this.tokens = tokens
    for (const listener of this.listeners) listener(tokens)
  }

  async fetchCaptcha(): Promise<CaptchaChallenge> {
    return this.request<CaptchaChallenge>('/auth/captcha')
  }

  async register(payload: RegisterPayload): Promise<{ message: string; email: string }> {
    return this.request('/auth/register', { method: 'POST', body: payload })
  }

  async login(payload: LoginPayload): Promise<LoginResult> {
    const result = await this.request<LoginResult>('/auth/login', { method: 'POST', body: payload })
    this.setTokens({
      access_token: result.access_token,
      refresh_token: result.refresh_token,
      token_type: result.token_type,
    })
    return result
  }

  async logout(): Promise<void> {
    try {
      // Best effort: if the server call fails the local session still ends.
      await this.request('/auth/logout', { method: 'POST', auth: true, allowRefresh: false })
    } finally {
      this.setTokens(null)
    }
  }

  async me(): Promise<UserProfile> {
    return this.request<UserProfile>('/users/me', { auth: true })
  }

  async verifyEmail(token: string, userId: string): Promise<void> {
    const query = new URLSearchParams({ token, user_id: userId })
    await this.request(`/auth/verify-email?${query.toString()}`, { method: 'POST' })
  }

  /**
   * Rotate the refresh token. Resolves to `null` when the session is over.
   * Concurrent callers share a single request so the token is consumed once.
   */
  private refresh(): Promise<TokenPair | null> {
    if (this.refreshInFlight) return this.refreshInFlight

    const current = this.tokens?.refresh_token
    if (!current) return Promise.resolve(null)

    this.refreshInFlight = (async () => {
      try {
        const pair = await this.request<TokenPair>(
          '/auth/refresh',
          { method: 'POST', body: { refresh_token: current } },
          false,
        )
        this.setTokens(pair)
        return pair
      } catch {
        this.setTokens(null)
        return null
      } finally {
        this.refreshInFlight = null
      }
    })()

    return this.refreshInFlight
  }

  private async request<T>(
    path: string,
    options: {
      method?: string
      body?: unknown
      auth?: boolean
      allowRefresh?: boolean
    } = {},
  ): Promise<T> {
    const { method = 'GET', body, auth = false, allowRefresh = true } = options
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (auth && this.tokens) headers.Authorization = `Bearer ${this.tokens.access_token}`

    const response = await fetch(`${this.base}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'omit',
    })

    if (response.status === 401 && auth && allowRefresh) {
      const pair = await this.refresh()
      if (pair) {
        return this.request<T>(path, { ...options, allowRefresh: false })
      }
    }

    if (!response.ok) {
      throw new ApiError(response.status, await readErrorMessage(response))
    }
    if (response.status === 204) return undefined as T
    return (await response.json()) as T
  }
}

/**
 * FastAPI returns `detail` as a string for handled errors, but as a list of
 * `{loc, msg}` objects for request-validation errors. Surface something
 * readable in both cases.
 */
async function readErrorMessage(response: Response): Promise<string> {
  let fallback = `Request failed (${response.status})`
  try {
    const data: unknown = await response.json()
    if (data && typeof data === 'object' && 'detail' in data) {
      const { detail } = data as { detail: unknown }
      if (typeof detail === 'string') return detail
      if (Array.isArray(detail)) {
        const messages = detail
          .map((entry) => {
            if (entry && typeof entry === 'object' && 'msg' in entry) {
              const { msg } = entry as { msg: unknown }
              return typeof msg === 'string' ? msg : null
            }
            return null
          })
          .filter((msg): msg is string => Boolean(msg))
        if (messages.length > 0) return messages.join('; ')
      }
    }
  } catch {
    // Non-JSON error body (proxy error page, gateway timeout, ...).
  }
  return fallback
}

export const api = new ApiClient()
