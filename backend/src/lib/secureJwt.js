const jwt = require('jsonwebtoken');
const dayjs = require('dayjs');
const { v4: uuid } = require('uuid');
const { secureConfig } = require('../config');

const refreshSessions = new Map();
const blacklistedAccessTokens = new Set();

function issueAccessToken(user) {
  const jti = uuid();
  const expiresAt = dayjs().add(secureConfig.accessTokenTtlSeconds, 'second');
  const token = jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role,
      provider: 'secure',
      type: 'access'
    },
    secureConfig.accessTokenSecret,
    {
      algorithm: 'HS256',
      expiresIn: secureConfig.accessTokenTtlSeconds,
      jwtid: jti
    }
  );

  return {
    token,
    meta: {
      jti,
      expiresAt: expiresAt.toISOString()
    }
  };
}

function issueRefreshToken(user) {
  const jti = uuid();
  const expiresAt = dayjs().add(secureConfig.refreshTokenTtlSeconds, 'second');
  const token = jwt.sign(
    {
      sub: user.id,
      type: 'refresh',
      jti
    },
    secureConfig.refreshTokenSecret,
    {
      algorithm: 'HS256',
      expiresIn: secureConfig.refreshTokenTtlSeconds
    }
  );

  refreshSessions.set(jti, {
    userId: user.id,
    revoked: false,
    expiresAt: expiresAt.toISOString()
  });

  return {
    token,
    meta: {
      jti,
      expiresAt: expiresAt.toISOString()
    }
  };
}

function verifyAccessToken(token, options = {}) {
  const payload = jwt.verify(token, secureConfig.accessTokenSecret, {
    algorithms: ['HS256'],
    ignoreExpiration: options.ignoreExpiration || false
  });

  if (payload.jti && blacklistedAccessTokens.has(payload.jti)) {
    const error = new Error('Access token blacklisted');
    error.name = 'TokenBlacklistedError';
    throw error;
  }

  return payload;
}

function verifyRefreshToken(token) {
  const payload = jwt.verify(token, secureConfig.refreshTokenSecret, {
    algorithms: ['HS256']
  });
  const session = refreshSessions.get(payload.jti);

  if (!session) {
    const error = new Error('Refresh token unknown');
    error.name = 'RefreshTokenNotFound';
    throw error;
  }

  if (session.revoked) {
    const error = new Error('Refresh token already rotated/revoked');
    error.name = 'RefreshTokenRevoked';
    throw error;
  }

  if (dayjs().isAfter(session.expiresAt)) {
    session.revoked = true;
    const error = new Error('Refresh token expired');
    error.name = 'RefreshTokenExpired';
    throw error;
  }

  return { payload, session };
}

function rotateRefreshToken(jti, user) {
  const session = refreshSessions.get(jti);
  if (session) {
    session.revoked = true;
  }
  return issueRefreshToken(user);
}

function revokeRefreshToken(jti) {
  const session = refreshSessions.get(jti);
  if (session) {
    session.revoked = true;
  }
}

function revokeAllUserRefreshTokens(userId) {
  refreshSessions.forEach((session, key) => {
    if (session.userId === userId) {
      refreshSessions.set(key, { ...session, revoked: true });
    }
  });
}

function blacklistAccessToken(jti) {
  if (jti) {
    blacklistedAccessTokens.add(jti);
  }
}

function getSecureStoreState() {
  return {
    refreshSessions: Array.from(refreshSessions.entries()).map(([jti, session]) => ({
      jti,
      ...session
    })),
    blacklistedAccessTokens: Array.from(blacklistedAccessTokens.values())
  };
}

module.exports = {
  issueAccessToken,
  issueRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  revokeAllUserRefreshTokens,
  blacklistAccessToken,
  getSecureStoreState
};

