/**
 * A stable per-browser identifier, used by the backend to group and revoke
 * refresh tokens per device.
 */
const STORAGE_KEY = 'enterprise-auth:device-id'

// Read once per page load: crypto.randomUUID() must not be called twice for
// the "same" device when storage is unavailable (private mode).
let cachedId: string | null = null

export function deviceLabel(): { id: string; name: string } {
  return { id: deviceId(), name: describeBrowser() }
}

function deviceId(): string {
  if (cachedId) return cachedId
  try {
    const existing = localStorage.getItem(STORAGE_KEY)
    if (existing) {
      cachedId = existing
      return existing
    }
    cachedId = crypto.randomUUID()
    localStorage.setItem(STORAGE_KEY, cachedId)
    return cachedId
  } catch {
    // Private mode or blocked storage: fall back to an id that lives for this
    // page load only. device_id is an opaque grouping key, so that is fine.
    cachedId = crypto.randomUUID()
    return cachedId
  }
}

function describeBrowser(): string {
  const ua = navigator.userAgent
  const browser = /Edg\//.test(ua)
    ? 'Edge'
    : /Firefox\//.test(ua)
      ? 'Firefox'
      : /Chrome\//.test(ua)
        ? 'Chrome'
        : /Safari\//.test(ua)
          ? 'Safari'
          : 'Browser'
  const platform = /Windows/.test(ua)
    ? 'Windows'
    : /Mac OS X/.test(ua)
      ? 'macOS'
      : /Android/.test(ua)
        ? 'Android'
        : /iPhone|iPad/.test(ua)
          ? 'iOS'
          : /Linux/.test(ua)
            ? 'Linux'
            : ''
  return platform ? `${browser} on ${platform}` : browser
}
