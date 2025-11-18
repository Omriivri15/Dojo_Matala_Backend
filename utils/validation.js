// Simple email validation: text@domain.com
const isValidEmail = (email) => {
  if (!email || typeof email !== 'string') return false;
  const parts = email.split('@');
  if (parts.length !== 2) return false;
  const [name, domain] = parts;
  if (!name || name.length === 0) return false;
  if (!domain || !domain.endsWith('.com')) return false;
  const domainParts = domain.split('.');
  if (domainParts.length !== 2 || domainParts[1] !== 'com') return false;
  return true;
};

const isValidPassword = (password) => {
  return password && password.length >= 8;
};

module.exports = { isValidEmail, isValidPassword };

