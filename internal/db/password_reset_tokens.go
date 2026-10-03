package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/distr-sh/distr/internal/apierrors"
	internalctx "github.com/distr-sh/distr/internal/context"
	"github.com/distr-sh/distr/internal/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var passwordResetTokenOutputExpr = `
	id,
	created_at,
	user_account_id,
	expires_at,
	status,
	consumed_at
`

// ActivatePasswordResetToken records the given token as active after its mail was delivered and invalidates
// every other active token of the account. The user row is locked for the duration so that two deliveries
// completed at the same time resolve in a defined order: the activation that commits last leaves its token as
// the single active one.
func ActivatePasswordResetToken(ctx context.Context, token types.PasswordResetToken) error {
	return RunTx(ctx, func(ctx context.Context) error {
		db := internalctx.GetDb(ctx)
		if _, err := db.Exec(ctx,
			`SELECT id FROM UserAccount WHERE id = @user_id FOR UPDATE`,
			pgx.NamedArgs{"user_id": token.UserAccountID},
		); err != nil {
			return fmt.Errorf("could not lock user account: %w", err)
		}
		if _, err := db.Exec(ctx,
			`INSERT INTO UserAccount_PasswordResetToken (id, user_account_id, expires_at, status)
			 VALUES (@id, @user_id, @expires_at, 'active'::PASSWORD_RESET_TOKEN_STATUS)`,
			pgx.NamedArgs{
				"id":         token.ID,
				"user_id":    token.UserAccountID,
				"expires_at": token.ExpiresAt,
			},
		); err != nil {
			return fmt.Errorf("could not create password reset token: %w", err)
		}
		if _, err := db.Exec(ctx,
			`UPDATE UserAccount_PasswordResetToken
			 SET status = 'superseded'::PASSWORD_RESET_TOKEN_STATUS
			 WHERE user_account_id = @user_id AND id != @id
			   AND status = 'active'::PASSWORD_RESET_TOKEN_STATUS`,
			pgx.NamedArgs{"user_id": token.UserAccountID, "id": token.ID},
		); err != nil {
			return fmt.Errorf("could not supersede password reset tokens: %w", err)
		}
		return nil
	})
}

func GetPasswordResetToken(ctx context.Context, id uuid.UUID) (*types.PasswordResetToken, error) {
	db := internalctx.GetDb(ctx)
	rows, err := db.Query(ctx,
		`SELECT `+passwordResetTokenOutputExpr+`
		 FROM UserAccount_PasswordResetToken
		 WHERE id = @id`,
		pgx.NamedArgs{"id": id},
	)
	if err != nil {
		return nil, fmt.Errorf("could not query password reset token: %w", err)
	}
	token, err := pgx.CollectExactlyOneRow[types.PasswordResetToken](rows, pgx.RowToStructByPos)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apierrors.ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("could not read password reset token: %w", err)
	}
	return &token, nil
}

// ConsumePasswordResetToken marks the token consumed in a single conditional statement, so two concurrent
// confirmations of the same token can affect only one row. It also invalidates every other outstanding token
// of the account. It returns false without an error when the token is no longer consumable; the caller then
// classifies why from the stored row.
func ConsumePasswordResetToken(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	db := internalctx.GetDb(ctx)
	if _, err := db.Exec(ctx,
		`UPDATE UserAccount_PasswordResetToken
		 SET status = 'superseded'::PASSWORD_RESET_TOKEN_STATUS
		 WHERE user_account_id = @user_id AND id != @id
		   AND status = 'active'::PASSWORD_RESET_TOKEN_STATUS`,
		pgx.NamedArgs{"user_id": userID, "id": id},
	); err != nil {
		return false, fmt.Errorf("could not supersede password reset tokens: %w", err)
	}
	cmd, err := db.Exec(ctx,
		`UPDATE UserAccount_PasswordResetToken
		 SET status = 'consumed'::PASSWORD_RESET_TOKEN_STATUS, consumed_at = now()
		 WHERE id = @id AND user_account_id = @user_id
		   AND status = 'active'::PASSWORD_RESET_TOKEN_STATUS AND expires_at > now()`,
		pgx.NamedArgs{"id": id, "user_id": userID},
	)
	if err != nil {
		return false, fmt.Errorf("could not consume password reset token: %w", err)
	}
	return cmd.RowsAffected() == 1, nil
}
