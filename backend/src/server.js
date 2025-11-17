require('dotenv').config();

const express = require('express');
const cors = require('cors');
const dayjs = require('dayjs');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');

const {
  findUser,
  findUserById,
  verifyPassword,
  toPublicProfile
} = require('./data/users');
const {
  createNoneAlgToken,
  decodeWithoutVerify,
  signWithWeakSecret,
  verifyWithWeakSecret,
  base64UrlDecode
} = require('./lib/insecureJwt');
const {
  issueAccessToken,
  issueRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  revokeAllUserRefreshTokens,
  blacklistAccessToken,
  getSecureStoreState
} = require('./lib/secureJwt');
const { secureConfig, insecureConfig } = require('./config');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const defaultWordlist = [
  'secret',
  'password',
  'password123',
  'letmein',
  'hunter2',
  insecureConfig.weakSecret
];

const insecureSessions = new Map();
const tokenUsage = new Map();

function trackTokenUsage(token) {
  if (!token) return null;
  const entry = tokenUsage.get(token) || {
    firstSeen: dayjs().toISOString(),
    count: 0
  };
  entry.count += 1;
  entry.lastSeen = dayjs().toISOString();
  tokenUsage.set(token, entry);
  return entry;
}

function extractBearerToken(req) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.toLowerCase().startsWith('bearer ')) {
    return null;
  }
  return authHeader.slice(7).trim();
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

/**
 * INSECURE ENDPOINTS
 */
app.post('/api/insecure/login', (req, res) => {
  const { username, password } = req.body || {};

  const user = findUser(username);
  if (!user || !verifyPassword(user, password)) {
    return res.status(401).json({ message: 'Invalid credentials (still required)' });
  }

  const basePayload = {
    sub: user.id,
    username: user.username,
    role: user.role,
    provider: 'insecure',
    session: uuid()
  };

  const noneToken = createNoneAlgToken(basePayload);
  const weakToken = signWithWeakSecret(basePayload);
  const sessionId = uuid();

  insecureSessions.set(sessionId, {
    userId: user.id,
    issuedAt: dayjs().toISOString(),
    tokens: { noneToken, weakToken }
  });

  res.json({
    sessionId,
    user: toPublicProfile(user),
    tokens: {
      none: noneToken,
      weak: weakToken
    },
    warnings: [
      'alg set to none → signature ignored',
      'weak shared secret',
      'tokens never expire',
      'server keeps zero logout state'
    ]
  });
});

app.post('/api/insecure/dashboard', (req, res) => {
  const token = req.body?.token || req.headers['x-insecure-token'];
  if (!token) {
    return res.status(401).json({ message: 'Token required' });
  }

  const decoded = decodeWithoutVerify(token);
  if (!decoded) {
    return res.status(400).json({ message: 'Token could not be decoded' });
  }

  const usage = trackTokenUsage(token);
  res.json({
    decoded,
    message: `👋 ${decoded.username}, this dashboard trusts anything it sees in the payload.`,
    usage
  });
});

app.post('/api/insecure/admin', (req, res) => {
  const token = req.body?.token;
  const decoded = decodeWithoutVerify(token);
  if (!decoded) {
    return res.status(400).json({ message: 'Invalid token payload' });
  }

  if (decoded.role !== 'admin') {
    return res.status(403).json({
      message: 'Access denied – but feel free to tamper with the token and try again!'
    });
  }

  const usage = trackTokenUsage(token);
  res.json({
    flag: 'ADMIN_ACCESS_GRANTED',
    decoded,
    usage
  });
});

app.post('/api/insecure/logout', (req, res) => {
  const { sessionId } = req.body || {};
  // Intentionally do nothing to simulate no server-side session invalidation.
  if (sessionId) {
    insecureSessions.delete(sessionId);
  }
  res.json({
    message: 'Logged out locally only. Token still valid → replay attack ready.'
  });
});

app.post('/api/insecure/verify-weak', (req, res) => {
  const { token } = req.body || {};
  if (!token) {
    return res.status(400).json({ message: 'Token required' });
  }
  const payload = verifyWithWeakSecret(token);
  if (!payload) {
    return res.status(400).json({ message: 'Signature check failed with weak secret' });
  }
  res.json({ payload });
});

/**
 * ATTACK UTILITIES
 */
app.post('/api/attacks/bruteforce', (req, res) => {
  const { token, candidates } = req.body || {};
  if (!token) {
    return res.status(400).json({ message: 'Provide a token to crack' });
  }

  const wordlist = Array.isArray(candidates) && candidates.length ? candidates : defaultWordlist;
  let attempts = 0;
  for (const guess of wordlist) {
    attempts += 1;
    try {
      jwt.verify(token, guess, { algorithms: ['HS256'] });
      return res.json({
        success: true,
        secret: guess,
        attempts
      });
    } catch (err) {
      continue;
    }
  }

  res.json({
    success: false,
    attempts,
    message: 'Secret not found in supplied wordlist'
  });
});

app.post('/api/attacks/forge', (req, res) => {
  const { algorithm = 'none', payload, secret } = req.body || {};
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ message: 'Payload object required' });
  }

  if (algorithm === 'none') {
    return res.json({
      token: createNoneAlgToken(payload)
    });
  }

  if (algorithm.toLowerCase() === 'hs256') {
    if (!secret) {
      return res.status(400).json({ message: 'Secret required for HS256 forgery' });
    }
    const token = jwt.sign(payload, secret, { algorithm: 'HS256' });
    return res.json({ token });
  }

  res.status(400).json({ message: `Unsupported algorithm ${algorithm}` });
});

app.post('/api/tools/decode', (req, res) => {
  const { token } = req.body || {};
  if (!token) {
    return res.status(400).json({ message: 'Token required' });
  }

  const [rawHeader, rawPayload, rawSignature = ''] = token.split('.');
  try {
    const decoded = {
      header: JSON.parse(base64UrlDecode(rawHeader)),
      payload: JSON.parse(base64UrlDecode(rawPayload)),
      signature: rawSignature
    };
    res.json({ decoded });
  } catch (err) {
    res.status(400).json({ message: 'Failed to decode token', error: err.message });
  }
});

app.post('/api/tools/replay-usage', (req, res) => {
  const { token } = req.body || {};
  if (!token || !tokenUsage.has(token)) {
    return res.status(404).json({ message: 'No usage recorded yet' });
  }
  res.json({ usage: tokenUsage.get(token) });
});

/**
 * SECURE ENDPOINTS
 */
app.post('/api/secure/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = findUser(username);
  if (!user || !verifyPassword(user, password)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const { token: accessToken, meta: accessMeta } = issueAccessToken(user);
  const { token: refreshToken, meta: refreshMeta } = issueRefreshToken(user);

  res.json({
    user: toPublicProfile(user),
    accessToken,
    refreshToken,
    meta: {
      access: accessMeta,
      refresh: refreshMeta
    }
  });
});

app.get('/api/secure/dashboard', (req, res) => {
  const token = extractBearerToken(req);
  if (!token) {
    return res.status(401).json({ message: 'Authorization header missing' });
  }

  try {
    const payload = verifyAccessToken(token);
    const user = findUserById(payload.sub);
    res.json({
      user: toPublicProfile(user),
      payload,
      message: `Welcome back ${user.username}. Token expires quickly and is rotated.`
    });
  } catch (err) {
    res.status(401).json({ message: err.message });
  }
});

app.post('/api/secure/refresh', (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token required' });
  }

  try {
    const { payload } = verifyRefreshToken(refreshToken);
    const user = findUserById(payload.sub);
    if (!user) {
      return res.status(401).json({ message: 'User no longer exists' });
    }

    const { token: newAccessToken, meta: accessMeta } = issueAccessToken(user);
    const { token: newRefreshToken, meta: refreshMeta } = rotateRefreshToken(payload.jti, user);

    res.json({
      user: toPublicProfile(user),
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      meta: {
        access: accessMeta,
        refresh: refreshMeta,
        rotatedFrom: payload.jti
      }
    });
  } catch (err) {
    res.status(401).json({ message: err.message });
  }
});

app.post('/api/secure/logout', (req, res) => {
  const { refreshToken, revokeAllSessions } = req.body || {};
  const accessToken = extractBearerToken(req);

  if (accessToken) {
    try {
      const payload = verifyAccessToken(accessToken, { ignoreExpiration: true });
      blacklistAccessToken(payload.jti);
      if (revokeAllSessions) {
        revokeAllUserRefreshTokens(payload.sub);
      }
    } catch (err) {
      // ignore – token may already be expired/invalid
    }
  }

  if (refreshToken) {
    try {
      const { payload } = verifyRefreshToken(refreshToken);
      revokeRefreshToken(payload.jti);
    } catch (err) {
      // already revoked/expired
    }
  }

  res.json({ message: 'Session revoked. Access token blacklisted, refresh rotated.' });
});

app.get('/api/secure/state', (req, res) => {
  res.json(getSecureStoreState());
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Unexpected server error', detail: err.message });
});

app.listen(PORT, () => {
  console.log(`JWT attack lab backend listening on http://localhost:${PORT}`);
});

