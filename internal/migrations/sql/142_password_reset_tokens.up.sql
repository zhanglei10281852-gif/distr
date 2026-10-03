CREATE TYPE PASSWORD_RESET_TOKEN_STATUS AS ENUM ('active', 'superseded', 'consumed');

CREATE TABLE UserAccount_PasswordResetToken (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  user_account_id UUID NOT NULL REFERENCES UserAccount(id) ON DELETE CASCADE,
  expires_at TIMESTAMP NOT NULL,
  status PASSWORD_RESET_TOKEN_STATUS NOT NULL DEFAULT 'active',
  consumed_at TIMESTAMP
);

CREATE INDEX idx_UserAccount_PasswordResetToken_user_status
  ON UserAccount_PasswordResetToken(user_account_id, status);
