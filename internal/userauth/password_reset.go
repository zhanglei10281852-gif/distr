package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/distr-sh/distr/internal/apierrors"
	"github.com/distr-sh/distr/internal/db"
	"github.com/distr-sh/distr/internal/types"
	"github.com/google/uuid"
)

var (
	ErrResetLinkInvalid    = errors.New("password reset link is invalid")
	ErrResetLinkUsed       = errors.New("password reset link has already been used")
	ErrResetLinkSuperseded = errors.New("password reset link has been superseded")
	ErrResetLinkExpired    = errors.New("password reset link has expired")
)

// classifyPasswordResetToken maps the stored state of a reset token to the stable failure the endpoint
// returns. A token that belongs to another account is indistinguishable from one that does not exist, so a
// valid signature never reveals anything about an account.
func classifyPasswordResetToken(token *types.PasswordResetToken, userID uuid.UUID, now time.Time) error {
	if token.UserAccountID != userID {
		return ErrResetLinkInvalid
	}
	switch token.Status {
	case types.PasswordResetTokenStatusConsumed:
		return ErrResetLinkUsed
	case types.PasswordResetTokenStatusSuperseded:
		return ErrResetLinkSuperseded
	case types.PasswordResetTokenStatusActive:
		if !token.ExpiresAt.After(now) {
			return ErrResetLinkExpired
		}
		return nil
	default:
		return ErrResetLinkInvalid
	}
}

// ValidatePasswordResetLink verifies that the identity carried by a reset token is the account's current
// usable one. Called inside the confirm transaction before any credential is changed.
func ValidatePasswordResetLink(ctx context.Context, user types.UserAccount, id uuid.UUID) error {
	token, err := db.GetPasswordResetToken(ctx, id)
	if errors.Is(err, apierrors.ErrNotFound) {
		return ErrResetLinkInvalid
	} else if err != nil {
		return err
	}
	return classifyPasswordResetToken(token, user.ID, time.Now())
}

// ConsumePasswordResetLink marks the identity consumed and invalidates the account's other outstanding
// links. When the identity lost a concurrent confirmation, the stored row is classified into the same stable
// failure as a link presented on its own.
func ConsumePasswordResetLink(ctx context.Context, user types.UserAccount, id uuid.UUID) error {
	consumed, err := db.ConsumePasswordResetToken(ctx, user.ID, id)
	if err != nil {
		return err
	}
	if consumed {
		return nil
	}
	token, err := db.GetPasswordResetToken(ctx, id)
	if errors.Is(err, apierrors.ErrNotFound) {
		return ErrResetLinkInvalid
	} else if err != nil {
		return err
	}
	return classifyPasswordResetToken(token, user.ID, time.Now())
}
