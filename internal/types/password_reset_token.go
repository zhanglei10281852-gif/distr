package types

import (
	"time"

	"github.com/google/uuid"
)

type PasswordResetTokenStatus string

const (
	PasswordResetTokenStatusActive     PasswordResetTokenStatus = "active"
	PasswordResetTokenStatusSuperseded PasswordResetTokenStatus = "superseded"
	PasswordResetTokenStatusConsumed   PasswordResetTokenStatus = "consumed"
)

type PasswordResetToken struct {
	ID            uuid.UUID                `db:"id"`
	CreatedAt     time.Time                `db:"created_at"`
	UserAccountID uuid.UUID                `db:"user_account_id"`
	ExpiresAt     time.Time                `db:"expires_at"`
	Status        PasswordResetTokenStatus `db:"status"`
	ConsumedAt    *time.Time               `db:"consumed_at"`
}
