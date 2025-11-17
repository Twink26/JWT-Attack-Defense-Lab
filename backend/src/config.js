const insecureConfig = {
  weakSecret: "password123",
  noneHeader: {
    alg: "none",
    typ: "JWT"
  },
  replayWindowMinutes: 60
};

const secureConfig = {
  accessTokenSecret: process.env.ACCESS_TOKEN_SECRET || "super-strong-access-secret-change-me",
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || "super-strong-refresh-secret-change-me",
  accessTokenTtlSeconds: 300,
  refreshTokenTtlSeconds: 86400
};

module.exports = {
  insecureConfig,
  secureConfig
};
