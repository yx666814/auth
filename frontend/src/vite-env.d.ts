/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Proxy target used by the Vite dev/preview server for /api requests. */
  readonly VITE_PROXY_TARGET?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
