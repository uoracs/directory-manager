package ldap

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/uoracs/directory-manager/internal/config"
	"github.com/uoracs/directory-manager/internal/keys"
)

// GetUidOfExistingUser looks up the uidNumber (UNIX ID) of a user in AD.
// If uidNumber isn't populated in AD, you may want to return the objectSid instead.
func GetUidOfExistingUser(ctx context.Context, username string) (string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}

	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return "", fmt.Errorf("LDAP connection not found in context")
	}

	// Build search request against the Users base DN
	searchRequest := ldap.NewSearchRequest(
		cfg.LDAPUsersBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		// Filter: find the user by sAMAccountName
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(username)),
		[]string{"sAMAccountName", "uidNumber", "objectSid"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("failed to search LDAP: %w", err)
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("user %s not found", username)
	}

	// Try uidNumber first
	uid := sr.Entries[0].GetAttributeValue("uidNumber")
	if uid == "" {
		// Fallback: SID
		uid = sr.Entries[0].GetAttributeValue("objectSid")
	}

	return uid, nil
}
