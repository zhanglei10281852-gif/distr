package userauth

import (
	"testing"
	"time"

	"github.com/distr-sh/distr/internal/types"
	"github.com/google/uuid"
	. "github.com/onsi/gomega"
)

func TestClassifyPasswordResetToken(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	token := func(
		status types.PasswordResetTokenStatus,
		user uuid.UUID,
		expiresAt time.Time,
	) *types.PasswordResetToken {
		return &types.PasswordResetToken{
			ID:            uuid.MustParse("22222222-2222-2222-2222-222222222222"),
			UserAccountID: user,
			ExpiresAt:     expiresAt,
			Status:        status,
		}
	}

	for _, tc := range []struct {
		name   string
		token  *types.PasswordResetToken
		expect error
	}{
		{
			name:   "active and unexpired",
			token:  token(types.PasswordResetTokenStatusActive, userID, now.Add(time.Hour)),
			expect: nil,
		},
		{
			name:   "expiring exactly now",
			token:  token(types.PasswordResetTokenStatusActive, userID, now),
			expect: ErrResetLinkExpired,
		},
		{
			name:   "expired",
			token:  token(types.PasswordResetTokenStatusActive, userID, now.Add(-time.Second)),
			expect: ErrResetLinkExpired,
		},
		{
			name:   "consumed",
			token:  token(types.PasswordResetTokenStatusConsumed, userID, now.Add(time.Hour)),
			expect: ErrResetLinkUsed,
		},
		{
			name:   "superseded even when unexpired",
			token:  token(types.PasswordResetTokenStatusSuperseded, userID, now.Add(time.Hour)),
			expect: ErrResetLinkSuperseded,
		},
		{
			name:   "belongs to another account",
			token:  token(types.PasswordResetTokenStatusActive, uuid.New(), now.Add(time.Hour)),
			expect: ErrResetLinkInvalid,
		},
		{
			name:   "unknown status",
			token:  token(types.PasswordResetTokenStatus("unexpected"), userID, now.Add(time.Hour)),
			expect: ErrResetLinkInvalid,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			err := classifyPasswordResetToken(tc.token, userID, now)
			if tc.expect == nil {
				g.Expect(err).To(Succeed())
			} else {
				g.Expect(err).To(MatchError(tc.expect))
			}
		})
	}
}
