package ldap

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/uoracs/directory-manager/internal/config"
	"github.com/uoracs/directory-manager/internal/keys"
)

var (
	err                   error
	found                 bool
	topLevelUsersGroupDN  = "CN=IS.RACS.Talapas.Users,OU=RACS,OU=Groups,OU=IS,OU=Units,DC=ad,DC=uoregon,DC=edu"
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
func RemoveUserFromTalapasMaster(ctx context.Context, username string) (string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}

	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return "", fmt.Errorf("LDAP connection not found in context")
	}
	// Define the DN for the is.racs.talapas.users group
	groupDN := topLevelUsersGroupDN
	// Search for the user DN
	searchRequest := ldap.NewSearchRequest(
		cfg.LDAPUsersBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(username)),
		[]string{"distinguishedName"},
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("failed to search LDAP for user %s: %w", username, err)
	}
	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("user %s not found in LDAP", username)
	}

	userDN := sr.Entries[0].GetAttributeValue("distinguishedName")

	// Verify the user is currently a member of the group
	groupSearch := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN)),
		[]string{"member"},
		nil,
	)

	groupResult, err := l.Search(groupSearch)
	if err != nil {
		return "", fmt.Errorf("failed to search group %s: %w", groupDN, err)
	}

	if len(groupResult.Entries) == 0 {
		return "", fmt.Errorf("user %s is not a member of %s", username, groupDN)
	}

	if err := RemoveUserFromGroup(ctx, groupDN, userDN); err != nil {
		return "", fmt.Errorf("failed to remove user %s from group %s: %w", username, groupDN, err)
	}

	return fmt.Sprintf("Successfully removed %s from %s", username, groupDN), nil
}
