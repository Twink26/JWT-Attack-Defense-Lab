const jwt = require('jsonwebtoken');
const dayjs = require('dayjs');
const { insecureConfig } = require('../config');

function base64UrlEncode(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(segment) {
  if (!segment) return '';
  let normalized = segment.replace(/-/g, '+').replace(/_/g, '/');
  while (normalized.length % 4 !== 0) {
    normalized += '=';
  }
  return Buffer.from(normalized, 'base64').toString('utf8');
}

function createNoneAlgToken(payload) {
  const header = insecureConfig.noneHeader;
  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode({
    ...payload,
    issuedAt: dayjs().toISOString()
  });
  return `${encodedHeader}.${encodedPayload}.`;
}

function decodeWithoutVerify(token) {
  try {
    const [, payload] = token.split('.');
    const json = base64UrlDecode(payload);
    return JSON.parse(json);
  } catch (err) {
    return null;
  }
}

function signWithWeakSecret(payload) {
  return jwt.sign(
    {
      ...payload,
      iat: Math.floor(Date.now() / 1000)
    },
    insecureConfig.weakSecret,
    { algorithm: 'HS256', mutatePayload: false }
  );
}

function verifyWithWeakSecret(token) {
  try {
    return jwt.verify(token, insecureConfig.weakSecret, { algorithms: ['HS256'] });
  } catch (err) {
    return null;
  }
}

module.exports = {
  createNoneAlgToken,
  base64UrlEncode,
  base64UrlDecode,
  decodeWithoutVerify,
  signWithWeakSecret,
  verifyWithWeakSecret
};
