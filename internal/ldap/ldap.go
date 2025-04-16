package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	"github.com/lcrownover/directory-manager/internal/config"
	"github.com/lcrownover/directory-manager/internal/keys"
)

func LoadLDAPConnection(ctx context.Context) (context.Context, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	connStr := fmt.Sprintf("ldaps://%s:%d", cfg.LDAPServer, cfg.LDAPPort)
	l, err := ldap.DialURL(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	err = l.Bind(cfg.LDAPUsername, cfg.LDAPPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to LDAP server: %w", err)
	}

	return context.WithValue(ctx, keys.LDAPConnKey, l), nil
}

func GetExistingGroupsWithGidNumbers(ctx context.Context) (map[string]int, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return nil, fmt.Errorf("LDAP connection not found in context")
	}
	searchRequest := ldap.NewSearchRequest(
		cfg.LDAPGroupsBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=group)(gidNumber=*))",
		[]string{"cn", "gidNumber"},
		nil,
	)
	slog.Debug("Searching LDAP for existing groups with gid numbers", "baseDN", cfg.LDAPGroupsBaseDN)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %w", err)
	}

	existing := make(map[string]int)
	for _, entry := range sr.Entries {
		gid, err := strconv.Atoi(entry.GetAttributeValue("gidNumber"))
		if err != nil {
			continue
		}
		existing[entry.GetAttributeValue("cn")] = gid
	}

	return existing, nil
}

func CreateOU(ctx context.Context, baseDN string, name string) error {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return fmt.Errorf("LDAP connection not found in context")
	}

	// Construct the DN for the new group.
	ouDN := fmt.Sprintf("OU=%s,%s", name, baseDN)

	// Check if the DN already exists.
	exists, err := DNExists(ctx, ouDN)
	if err != nil {
		return fmt.Errorf("failed to check if OU exists: %w", err)
	}
	if exists {
		return nil
	}

	// Create a new add request.
	addRequest := ldap.NewAddRequest(ouDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "organizationalUnit"})
	addRequest.Attribute("ou", []string{name})

	// Execute the add request.
	if err := l.Add(addRequest); err != nil {
		return fmt.Errorf("failed to add group %s: %w", name, err)
	}

	return nil
}

func CreateADGroup(ctx context.Context, baseDN string, name string, gidNumber int) error {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return fmt.Errorf("LDAP connection not found in context")
	}

	// Construct the DN for the new group.
	// This example assumes groups are created directly under the given baseDN.
	groupDN := fmt.Sprintf("CN=%s,%s", name, baseDN)

	// Check if the group already exists.
	exists, err := DNExists(ctx, groupDN)
	if err != nil {
		return fmt.Errorf("failed to check if group exists: %w", err)
	}
	if exists {
		return nil
	}

	// Create a new add request.
	// Note: In AD with Unix extensions, a group may include both the "group" and "posixGroup" object classes.
	addRequest := ldap.NewAddRequest(groupDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "group", "posixGroup"})
	addRequest.Attribute("cn", []string{name})
	// sAMAccountName is required by AD. Often it can be the same as the cn.
	addRequest.Attribute("sAMAccountName", []string{name})
	// groupType attribute is required in AD to determine the kind of group.
	// Here we use -2147483646 which represents a global security group.
	addRequest.Attribute("groupType", []string{"-2147483646"})
	// Set the gidNumber attribute as a string.
	addRequest.Attribute("gidNumber", []string{strconv.Itoa(gidNumber)})

	// Execute the add request.
	if err := l.Add(addRequest); err != nil {
		return fmt.Errorf("failed to add group %s: %w", name, err)
	}

	return nil
}

func AddUserToGroup(ctx context.Context, groupDN string, userDN string) error {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return fmt.Errorf("LDAP connection not found in context")
	}

	// Create a new modify request to add the user to the group.
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)
	modifyRequest.Add("member", []string{userDN})

	// Execute the modify request.
	if err := l.Modify(modifyRequest); err != nil {
		return fmt.Errorf("failed to add user %s to group %s: %w", userDN, groupDN, err)
	}

	return nil
}

func GetUserDN(ctx context.Context, username string) (string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return "", fmt.Errorf("LDAP connection not found in context")
	}
	baseDN := cfg.LDAPUsersBaseDN
	// Build a search filter.
	// The filter targets persons with a matching sAMAccountName.
	filter := fmt.Sprintf("(&(objectCategory=person)(sAMAccountName=%s))", ldap.EscapeFilter(username))

	// Construct the search request.
	searchRequest := ldap.NewSearchRequest(
		baseDN,                 // The base DN for the search.
		ldap.ScopeWholeSubtree, // Search the whole tree.
		ldap.NeverDerefAliases, // Never dereference aliases.
		0,                      // No size limit.
		0,                      // No time limit.
		false,                  // TypesOnly false, retrieve both attributes and values.
		filter,                 // The search filter.
		[]string{"dn"},         // We only need the DN attribute.
		nil,                    // No additional controls.
	)

	// Execute the search.
	sr, err := l.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("LDAP search failed: %v", err)
	}

	// Check if we got any results.
	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("user %q not found", username)
	}

	// Return the distinguished name of the first matching entry.
	return sr.Entries[0].DN, nil
}

func GetGroupDN(ctx context.Context, groupname string) (string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return "", fmt.Errorf("LDAP connection not found in context")
	}
	baseDN := cfg.LDAPGroupsBaseDN
	// Build a search filter.
	// The filter targets groups with a matching cn.
	filter := fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(groupname))

	// Construct the search request.
	searchRequest := ldap.NewSearchRequest(
		baseDN,                 // The base DN for the search.
		ldap.ScopeWholeSubtree, // Search the whole tree.
		ldap.NeverDerefAliases, // Never dereference aliases.
		0,                      // No size limit.
		0,                      // No time limit.
		false,                  // TypesOnly false, retrieve both attributes and values.
		filter,                 // The search filter.
		[]string{"dn"},         // We only need the DN attribute.
		nil,                    // No additional controls.
	)

	// Execute the search.
	sr, err := l.Search(searchRequest)
	if err != nil {
		// Handle the case where the group does not exist, this is not an error
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			return "", nil
		}
		return "", fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("group %q not found", groupname)
	}

	return sr.Entries[0].DN, nil
}

func DNExists(ctx context.Context, dn string) (bool, error) {
	slog.Debug("Checking if DN exists", "dn", dn)
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return false, fmt.Errorf("LDAP connection not found in context")
	}

	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		nil,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		// Handle the case where the DN does not exist, this is not an error
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			return false, nil
		}
		return false, fmt.Errorf("failed to search LDAP: %w", err)
	}

	return len(sr.Entries) > 0, nil
}
