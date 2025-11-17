const bcrypt = require('bcryptjs');

const rawUsers = [
  { id: 'u1', username: 'alice', password: 'alice123', role: 'user' },
  { id: 'u2', username: 'bob', password: 'bob123', role: 'user' },
  { id: 'admin1', username: 'admin', password: 'admin123', role: 'admin' }
];

const users = rawUsers.map((user) => ({
  ...user,
  passwordHash: bcrypt.hashSync(user.password, 8)
}));

function findUser(username) {
  return users.find((u) => u.username === username);
}

function findUserById(id) {
  return users.find((u) => u.id === id);
}

function verifyPassword(user, candidate) {
  return bcrypt.compareSync(candidate, user.passwordHash);
}

function toPublicProfile(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    role: user.role
  };
}

module.exports = {
  findUser,
  findUserById,
  verifyPassword,
  toPublicProfile
};
