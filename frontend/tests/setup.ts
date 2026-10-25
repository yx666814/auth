import '@testing-library/react'

// jsdom does not implement these; components call them for device identity
// and navigation, so they need a stand-in during tests.
if (!globalThis.crypto?.randomUUID) {
  Object.defineProperty(globalThis.crypto, 'randomUUID', {
    value: () => '00000000-0000-4000-8000-000000000000',
  })
}
