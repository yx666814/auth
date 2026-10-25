import { Link, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth/AuthProvider'
import { RedirectIfAuthed, RequireAuth } from './auth/guards'
import { AccountPage } from './pages/AccountPage'
import { LoginPage } from './pages/LoginPage'
import { RegisterPage } from './pages/RegisterPage'
import { VerifyEmailPage } from './pages/VerifyEmailPage'

function Header() {
  const { user } = useAuth()
  return (
    <header className="site-header">
      <Link to="/" className="brand">
        Enterprise Auth
      </Link>
      <nav>
        {user ? (
          <Link to="/account">Account</Link>
        ) : (
          <>
            <Link to="/login">Sign in</Link>
            <Link to="/register">Create account</Link>
          </>
        )}
      </nav>
    </header>
  )
}

function HomePage() {
  const { user } = useAuth()
  return (
    <main className="card">
      <h1>Enterprise Auth</h1>
      <p>Multi-tenant authentication with Argon2id passwords, rotating refresh tokens, and per-account lockout.</p>
      <p>
        {user ? (
          <Link to="/account">Go to your account</Link>
        ) : (
          <>
            <Link to="/login">Sign in</Link> or <Link to="/register">create an account</Link>.
          </>
        )}
      </p>
    </main>
  )
}

function NotFoundPage() {
  return (
    <main className="card">
      <h1>Page not found</h1>
      <p>
        <Link to="/">Back to the start</Link>
      </p>
    </main>
  )
}

export function App() {
  return (
    <AuthProvider>
      <Header />
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route
          path="/login"
          element={
            <RedirectIfAuthed>
              <LoginPage />
            </RedirectIfAuthed>
          }
        />
        <Route
          path="/register"
          element={
            <RedirectIfAuthed>
              <RegisterPage />
            </RedirectIfAuthed>
          }
        />
        <Route path="/verify-email" element={<VerifyEmailPage />} />
        <Route
          path="/account"
          element={
            <RequireAuth>
              <AccountPage />
            </RequireAuth>
          }
        />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </AuthProvider>
  )
}
