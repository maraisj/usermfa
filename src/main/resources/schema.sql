CREATE TABLE user (
  id       INTEGER PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password VARCHAR(64) NOT NULL,
  enabled  BOOLEAN NOT NULL,
  mfa_enabled BOOLEAN NOT NULL,
  mfa_secret VARCHAR(32) NULL);
