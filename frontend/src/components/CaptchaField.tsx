import { useEffect, useState } from 'react'
import { api, type CaptchaChallenge } from '../api/client'

interface Props {
  value: string
  onChange: (value: string) => void
  onChallenge: (challenge: CaptchaChallenge) => void
  /** Bump this to fetch a fresh challenge (e.g. after a failed submit). */
  reloadKey?: number
  disabled?: boolean
}

/**
 * Image captcha backed by /auth/captcha. The challenge is single use on the
 * server and is consumed even when verification fails, so a failed submit must
 * be followed by a new one: the parent bumps `reloadKey`, or the user clicks
 * the image.
 */
export function CaptchaField({ value, onChange, onChallenge, reloadKey = 0, disabled }: Props) {
  const [image, setImage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [localReloads, setLocalReloads] = useState(0)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    api
      .fetchCaptcha()
      .then((challenge) => {
        if (cancelled) return
        setImage(challenge.image)
        onChallenge(challenge)
      })
      .catch(() => {
        if (!cancelled) setError('Could not load the verification code')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [reloadKey, localReloads, onChallenge])

  return (
    <div className="field">
      <label htmlFor="captcha">Verification code</label>
      <div className="captcha-row">
        <input
          id="captcha"
          name="captcha"
          type="text"
          autoComplete="off"
          autoCapitalize="characters"
          spellCheck={false}
          maxLength={16}
          required
          value={value}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
        />
        <button
          type="button"
          className="captcha-image"
          onClick={() => {
            onChange('')
            setLocalReloads((n) => n + 1)
          }}
          disabled={disabled || loading}
          title="Load a different code"
        >
          {loading || !image ? (
            <span className="captcha-placeholder">Loading…</span>
          ) : (
            <img src={image} alt="Verification code" />
          )}
        </button>
      </div>
      {error ? (
        <p className="field-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  )
}
