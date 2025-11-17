import { useMemo, useState } from 'react';
import './App.css';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000';
const defaultForgePayload = JSON.stringify(
  {
    sub: 'u1',
    username: 'alice',
    role: 'admin',
    provider: 'insecure',
    note: 'crafted token'
  },
  null,
  2
);

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });

  let data = null;
  try {
    data = await response.json();
  } catch (err) {
    data = null;
  }

  if (!response.ok) {
    const message = data?.message || 'Request failed';
    throw new Error(message);
  }

  return data;
}

function Section({ title, description, children }) {
  return (
    <section className="card">
      <header>
        <h2>{title}</h2>
        {description && <p className="muted">{description}</p>}
      </header>
      {children}
    </section>
  );
}

function App() {
  const [status, setStatus] = useState('Ready to hack and then fix JWTs 💥');

  const [insecureForm, setInsecureForm] = useState({
    username: 'alice',
    password: 'alice123'
  });
  const [insecureSession, setInsecureSession] = useState(null);
  const [insecureTokens, setInsecureTokens] = useState({ none: '', weak: '' });
  const [dashboardPayload, setDashboardPayload] = useState(null);
  const [tokenEditor, setTokenEditor] = useState('');
  const [replayInfo, setReplayInfo] = useState(null);

  const [secureForm, setSecureForm] = useState({
    username: 'alice',
    password: 'alice123'
  });
  const [secureTokens, setSecureTokens] = useState({ access: '', refresh: '' });
  const [secureMeta, setSecureMeta] = useState(null);
  const [secureDashboard, setSecureDashboard] = useState(null);
  const [secureStore, setSecureStore] = useState(null);

  const [inspectorToken, setInspectorToken] = useState('');
  const [inspectorResult, setInspectorResult] = useState(null);
  const [bruteForceResult, setBruteForceResult] = useState(null);
  const [forgeInput, setForgeInput] = useState({
    algorithm: 'none',
    payload: defaultForgePayload,
    secret: 'password123'
  });
  const [forgedToken, setForgedToken] = useState('');

  const insecureNoneToken = insecureTokens.none;

  const updateStatus = (message) => {
    setStatus(message);
    setTimeout(() => setStatus('Ready'), 5000);
  };

  const handleInsecureLogin = async () => {
    try {
      setStatus('Logging into insecure API…');
      const data = await apiRequest('/api/insecure/login', {
        method: 'POST',
        body: JSON.stringify(insecureForm)
      });
      setInsecureSession({ id: data.sessionId, user: data.user });
      setInsecureTokens(data.tokens);
      setTokenEditor(data.tokens.none);
      setDashboardPayload(null);
      setReplayInfo(null);
      updateStatus('Insecure login success – tokens ready for tampering');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const callInsecureDashboard = async (token) => {
    if (!token) {
      updateStatus('Provide a token first');
      return;
    }
    try {
      setStatus('Sending token to vulnerable dashboard…');
      const data = await apiRequest('/api/insecure/dashboard', {
        method: 'POST',
        body: JSON.stringify({ token })
      });
      setDashboardPayload(data);
      setReplayInfo(data.usage);
      updateStatus('Dashboard accepted whatever payload you sent 😬');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const callInsecureAdmin = async () => {
    if (!tokenEditor) {
      updateStatus('Paste or forge a token first');
      return;
    }
    try {
      const data = await apiRequest('/api/insecure/admin', {
        method: 'POST',
        body: JSON.stringify({ token: tokenEditor })
      });
      setDashboardPayload(data);
      updateStatus('Admin area unlocked using forged payload!');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const logoutAndReplay = async () => {
    if (!insecureSession?.id) {
      updateStatus('No insecure session to logout from');
      return;
    }
    try {
      await apiRequest('/api/insecure/logout', {
        method: 'POST',
        body: JSON.stringify({ sessionId: insecureSession.id })
      });
      await callInsecureDashboard(tokenEditor || insecureNoneToken);
      updateStatus('Logout did nothing – replay succeeded');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const runBruteForce = async () => {
    if (!insecureTokens.weak) {
      updateStatus('Login insecurely first to grab a weak token');
      return;
    }
    try {
      const data = await apiRequest('/api/attacks/bruteforce', {
        method: 'POST',
        body: JSON.stringify({ token: insecureTokens.weak })
      });
      setBruteForceResult(data);
      updateStatus(data.success ? 'Weak secret cracked!' : 'Secret not cracked');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const forgeToken = async () => {
    try {
      const payload = JSON.parse(forgeInput.payload);
      const data = await apiRequest('/api/attacks/forge', {
        method: 'POST',
        body: JSON.stringify({
          algorithm: forgeInput.algorithm,
          payload,
          secret: forgeInput.secret
        })
      });
      setForgedToken(data.token);
      setTokenEditor(data.token);
      updateStatus('New token forged');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const runInspector = async () => {
    if (!inspectorToken) {
      updateStatus('Paste a token to inspect');
      return;
    }
    try {
      const data = await apiRequest('/api/tools/decode', {
        method: 'POST',
        body: JSON.stringify({ token: inspectorToken })
      });
      setInspectorResult(data.decoded);
      updateStatus('Token decoded');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const handleSecureLogin = async () => {
    try {
      const data = await apiRequest('/api/secure/login', {
        method: 'POST',
        body: JSON.stringify(secureForm)
      });
      setSecureTokens({
        access: data.accessToken,
        refresh: data.refreshToken
      });
      setSecureMeta(data.meta);
      setSecureDashboard(null);
      updateStatus('Secure login issued access + refresh tokens');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const fetchSecureDashboard = async () => {
    if (!secureTokens.access) {
      updateStatus('Login securely first');
      return;
    }
    try {
      const data = await apiRequest('/api/secure/dashboard', {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${secureTokens.access}`
        }
      });
      setSecureDashboard(data);
      updateStatus('Secure dashboard fetched with access token');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const refreshSecureToken = async () => {
    if (!secureTokens.refresh) {
      updateStatus('No refresh token available');
      return;
    }
    try {
      const data = await apiRequest('/api/secure/refresh', {
        method: 'POST',
        body: JSON.stringify({ refreshToken: secureTokens.refresh })
      });
      setSecureTokens({
        access: data.accessToken,
        refresh: data.refreshToken
      });
      setSecureMeta(data.meta);
      updateStatus('Token rotation complete – new pair issued');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const logoutSecure = async (revokeAll = false) => {
    if (!secureTokens.access && !secureTokens.refresh) {
      updateStatus('Nothing to revoke');
      return;
    }
    try {
      const headers = {};
      if (secureTokens.access) {
        headers.Authorization = `Bearer ${secureTokens.access}`;
      }
      await apiRequest('/api/secure/logout', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          refreshToken: secureTokens.refresh,
          revokeAllSessions: revokeAll
        })
      });
      setSecureTokens({ access: '', refresh: '' });
      setSecureMeta(null);
      setSecureDashboard(null);
      updateStatus('Secure session fully revoked');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const loadSecureStore = async () => {
    try {
      const data = await apiRequest('/api/secure/state');
      setSecureStore(data);
      updateStatus('Secure token store snapshot fetched');
    } catch (err) {
      updateStatus(err.message);
    }
  };

  const tokenPreview = useMemo(() => {
    if (!tokenEditor) return null;
    return `${tokenEditor.slice(0, 32)}…${tokenEditor.slice(-12)}`;
  }, [tokenEditor]);

  return (
    <div className="App">
      <header className="hero">
        <div>
          <p className="eyebrow">JWT Attack Lab</p>
          <h1>Break insecure JWTs. Observe real mitigations.</h1>
          <p>
            This playground ships two auth stacks: intentionally broken tokens (alg
            none, weak secrets, replayable) and a hardened HS256 implementation with
            rotation + blacklisting. Use the controls below to exploit and then defend.
          </p>
          <p className="status">Status: {status}</p>
        </div>
      </header>

      <main className="grid">
        <Section
          title="1️⃣ Insecure Login"
          description="Tokens never expire, alg: none header, HS256 secret = password123"
        >
          <div className="form-row">
            <input
              value={insecureForm.username}
              onChange={(e) => setInsecureForm({ ...insecureForm, username: e.target.value })}
              placeholder="username"
            />
            <input
              value={insecureForm.password}
              onChange={(e) => setInsecureForm({ ...insecureForm, password: e.target.value })}
              placeholder="password"
            />
            <button onClick={handleInsecureLogin}>Login</button>
          </div>
          <div className="token-list">
            <div>
              <p className="muted label">alg:none token</p>
              <textarea value={insecureTokens.none} readOnly spellCheck="false" />
            </div>
            <div>
              <p className="muted label">weak HS256 token</p>
              <textarea value={insecureTokens.weak} readOnly spellCheck="false" />
            </div>
          </div>
          <div className="form-row">
            <button onClick={() => callInsecureDashboard(tokenEditor || insecureNoneToken)}>
              View vulnerable dashboard
            </button>
            <button className="ghost" onClick={logoutAndReplay}>
              Logout → replay attack
            </button>
            <button className="danger" onClick={callInsecureAdmin}>
              Try admin escalation
            </button>
          </div>
          {dashboardPayload && (
            <pre className="result">{JSON.stringify(dashboardPayload, null, 2)}</pre>
          )}
          {replayInfo && (
            <p className="muted">
              Replay count: {replayInfo.count} · first seen {replayInfo.firstSeen}
            </p>
          )}
        </Section>

        <Section
          title="2️⃣ Attack Demonstrations"
          description="Modify payloads, brute-force weak secrets, forge admin claims."
        >
          <label className="muted label" htmlFor="token-editor">
            Token editor (change claims, roles, expiry etc.)
          </label>
          <textarea
            id="token-editor"
            value={tokenEditor}
            onChange={(e) => setTokenEditor(e.target.value)}
            placeholder="Paste or forge a JWT"
            spellCheck="false"
          />
          <div className="form-row">
            <button onClick={() => callInsecureDashboard(tokenEditor)}>Send to dashboard</button>
            <button onClick={callInsecureAdmin}>Send to admin route</button>
          </div>
          <div className="attack-panel">
            <div>
              <p className="muted label">Brute-force weak HS256 secret</p>
              <button onClick={runBruteForce}>Start attack</button>
              {bruteForceResult && (
                <pre className="result small">
                  {JSON.stringify(bruteForceResult, null, 2)}
                </pre>
              )}
            </div>
            <div>
              <p className="muted label">Forge a token</p>
              <select
                value={forgeInput.algorithm}
                onChange={(e) => setForgeInput({ ...forgeInput, algorithm: e.target.value })}
              >
                <option value="none">alg:none (signature skipped)</option>
                <option value="hs256">HS256 (needs secret)</option>
              </select>
              {forgeInput.algorithm === 'hs256' && (
                <input
                  value={forgeInput.secret}
                  onChange={(e) => setForgeInput({ ...forgeInput, secret: e.target.value })}
                  placeholder="Provide secret (hint: password123)"
                />
              )}
              <textarea
                value={forgeInput.payload}
                onChange={(e) => setForgeInput({ ...forgeInput, payload: e.target.value })}
                spellCheck="false"
              />
              <button onClick={forgeToken}>Forge token</button>
              {forgedToken && (
                <p className="muted">
                  Latest forged token preview: <code>{tokenPreview}</code>
                </p>
              )}
            </div>
          </div>
        </Section>

        <Section
          title="3️⃣ Secure Login"
          description="HS256 + strong secrets, 5 minute access tokens, refresh rotation & blacklist."
        >
          <div className="form-row">
            <input
              value={secureForm.username}
              onChange={(e) => setSecureForm({ ...secureForm, username: e.target.value })}
              placeholder="username"
            />
            <input
              value={secureForm.password}
              onChange={(e) => setSecureForm({ ...secureForm, password: e.target.value })}
              placeholder="password"
            />
            <button onClick={handleSecureLogin}>Login securely</button>
          </div>
          <div className="token-list">
            <div>
              <p className="muted label">Access token</p>
              <textarea value={secureTokens.access} readOnly spellCheck="false" />
            </div>
            <div>
              <p className="muted label">Refresh token</p>
              <textarea value={secureTokens.refresh} readOnly spellCheck="false" />
            </div>
          </div>
          <div className="form-row">
            <button onClick={fetchSecureDashboard}>Call secure dashboard</button>
            <button onClick={refreshSecureToken}>Rotate refresh token</button>
            <button className="ghost" onClick={() => logoutSecure(false)}>
              Logout current session
            </button>
            <button className="danger ghost" onClick={() => logoutSecure(true)}>
              Logout all sessions
            </button>
          </div>
          {secureDashboard && (
            <pre className="result">{JSON.stringify(secureDashboard, null, 2)}</pre>
          )}
          {secureMeta && (
            <pre className="result small">{JSON.stringify(secureMeta, null, 2)}</pre>
          )}
          <button className="ghost" onClick={loadSecureStore}>
            Inspect secure token store
          </button>
          {secureStore && (
            <pre className="result small">{JSON.stringify(secureStore, null, 2)}</pre>
          )}
        </Section>

        <Section
          title="4️⃣ JWT Inspector"
          description="Decode any token using the backend helper (no signature checks)."
        >
          <textarea
            value={inspectorToken}
            onChange={(e) => setInspectorToken(e.target.value)}
            placeholder="Paste JWT here"
            spellCheck="false"
          />
          <div className="form-row">
            <button onClick={runInspector}>Decode token</button>
            <button className="ghost" onClick={() => setInspectorResult(null)}>
              Clear
            </button>
          </div>
          {inspectorResult && (
            <pre className="result">{JSON.stringify(inspectorResult, null, 2)}</pre>
          )}
        </Section>
      </main>

      <footer className="muted">
        Backend: {API_BASE} · Verify mitigations by inspecting blacklists & refresh sessions.
      </footer>
    </div>
  );
}

export default App;
