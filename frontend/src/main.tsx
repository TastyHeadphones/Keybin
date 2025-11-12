import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

type User = {
  id: string;
  createdAt: string;
};

type Paste = {
  id: string;
  title?: string | null;
  content: string;
  createdAt: string;
  updatedAt: string;
  expiresAt?: string | null;
};

const MAX_PASTE_LENGTH = 64 * 1024;

const fetchJSON = async <T,>(input: RequestInfo, init?: RequestInit): Promise<T> => {
  const res = await fetch(input, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {})
    },
    credentials: 'include'
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed with status ${res.status}`);
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return (await res.json()) as T;
};

const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [pastes, setPastes] = useState<Paste[]>([]);
  const [loading, setLoading] = useState(true);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [expiresInMinutes, setExpiresInMinutes] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadData = async () => {
    try {
      const me = await fetchJSON<User>('/me');
      setUser(me);
      const pasteList = await fetchJSON<Paste[]>('/pastes');
      setPastes(pasteList);
    } catch (err) {
      setUser(null);
      setPastes([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const resetForm = () => {
    setTitle('');
    setContent('');
    setExpiresInMinutes('');
  };

  const handleCreatePaste = async (evt: React.FormEvent) => {
    evt.preventDefault();
    setError(null);

    if (!content.trim()) {
      setError('Paste content cannot be empty.');
      return;
    }

    const byteLength = new TextEncoder().encode(content).length;
    if (byteLength > MAX_PASTE_LENGTH) {
      setError('Paste is too large (64 KB max).');
      return;
    }

    setBusy(true);
    try {
      const expiresAt = expiresInMinutes
        ? new Date(Date.now() + Number(expiresInMinutes) * 60_000).toISOString()
        : null;

      const paste = await fetchJSON<Paste>('/pastes', {
        method: 'POST',
        body: JSON.stringify({ title: title || null, content, expiresAt })
      });
      setPastes((prev) => [paste, ...prev]);
      resetForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create paste.');
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this paste?')) return;
    try {
      await fetchJSON<void>(`/pastes/${id}`, { method: 'DELETE' });
      setPastes((prev) => prev.filter((p) => p.id !== id));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Delete failed');
    }
  };

  const copyPaste = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
    } catch (err) {
      alert('Copy failed.');
    }
  };

  const doRegistration = async () => {
    setBusy(true);
    setError(null);
    try {
      const options = await fetchJSON<
        Parameters<typeof startRegistration>[0] & { challengeId: string }
      >('/webauthn/registration/options', {
        method: 'POST'
      });
      const attestation = await startRegistration(options);
      const result = await fetchJSON<User>('/webauthn/registration/verify', {
        method: 'POST',
        body: JSON.stringify({ ...attestation, challengeId: options.challengeId })
      });
      setUser(result);
      const pasteList = await fetchJSON<Paste[]>('/pastes');
      setPastes(pasteList);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed.');
    } finally {
      setBusy(false);
    }
  };

  const doLogin = async () => {
    setBusy(true);
    setError(null);
    try {
      const options = await fetchJSON<
        Parameters<typeof startAuthentication>[0] & { challengeId: string }
      >('/webauthn/login/options', {
        method: 'POST'
      });
      const assertion = await startAuthentication(options);
      const result = await fetchJSON<User>('/webauthn/login/verify', {
        method: 'POST',
        body: JSON.stringify({ ...assertion, challengeId: options.challengeId })
      });
      setUser(result);
      const pasteList = await fetchJSON<Paste[]>('/pastes');
      setPastes(pasteList);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed.');
    } finally {
      setBusy(false);
    }
  };

  const logOut = async () => {
    await fetchJSON<void>('/logout', { method: 'POST' }).catch(() => undefined);
    setUser(null);
    setPastes([]);
  };

  const isReady = useMemo(() => !loading && !busy, [loading, busy]);

  return (
    <div className="app">
      <header className="app-header">
        <h1>Keybin</h1>
        <div className="header-actions">
          {user ? (
            <>
              <span className="user-tag">{user.id.slice(0, 8)}</span>
              <button onClick={logOut} disabled={!isReady}>
                Log out
              </button>
            </>
          ) : (
            <>
              <button onClick={doLogin} disabled={!isReady}>
                Sign in
              </button>
              <button onClick={doRegistration} disabled={!isReady}>
                Create passkey
              </button>
            </>
          )}
        </div>
      </header>
      <main className="app-body">
        {error && <p className="error-banner">{error}</p>}
        {user ? (
          <>
            <section className="card">
              <h2>New paste</h2>
              <form onSubmit={handleCreatePaste} className="stack">
                <input
                  value={title}
                  onChange={(evt) => setTitle(evt.target.value)}
                  placeholder="Title (optional)"
                  maxLength={128}
                />
                <textarea
                  value={content}
                  onChange={(evt) => setContent(evt.target.value)}
                  placeholder="Paste content"
                  rows={12}
                />
                <div className="form-footer">
                  <label>
                    Expires in (minutes)
                    <input
                      value={expiresInMinutes}
                      onChange={(evt) => setExpiresInMinutes(evt.target.value.replace(/[^0-9]/g, ''))}
                      placeholder="optional"
                      inputMode="numeric"
                    />
                  </label>
                  <span className="muted">
                    {new TextEncoder().encode(content).length} / {MAX_PASTE_LENGTH} bytes
                  </span>
                  <button type="submit" disabled={busy}>
                    Save paste
                  </button>
                </div>
              </form>
            </section>
            <section className="card">
              <h2>Your pastes</h2>
              {pastes.length === 0 ? (
                <p className="muted">No pastes yet.</p>
              ) : (
                <ul className="paste-list">
                  {pastes.map((paste) => (
                    <li key={paste.id}>
                      <div className="paste-header">
                        <div>
                          <h3>{paste.title || 'Untitled'}</h3>
                          <p className="muted small">
                            {new Date(paste.createdAt).toLocaleString()}
                            {paste.expiresAt && ` • Expires ${new Date(paste.expiresAt).toLocaleString()}`}
                          </p>
                        </div>
                        <div className="paste-actions">
                          <button onClick={() => copyPaste(paste.content)}>Copy</button>
                          <button onClick={() => handleDelete(paste.id)} className="danger">
                            Delete
                          </button>
                        </div>
                      </div>
                      <pre>{paste.content}</pre>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </>
        ) : (
          <section className="card centered">
            <p>Sign in with a passkey to start storing secure pastes.</p>
          </section>
        )}
      </main>
    </div>
  );
};

const root = createRoot(document.getElementById('root')!);
root.render(<App />);
