package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/uoracs/directory-manager/internal/config"
	"github.com/uoracs/directory-manager/internal/keys"
)

func ConvertDNToObjectName(dn string) (string, error) {
	parts := strings.Split(dn, ",")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid DN format")
	}
	head := parts[0]
	hparts := strings.Split(head, "=")
	if len(hparts) != 2 {
		return "", fmt.Errorf("invalid DN format")
	}
	return hparts[1], nil
}

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

func CreateGroup(ctx context.Context, baseDN string, name string, gidNumber int) error {
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
		// Handle the case where the user is already a member of the group.
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultEntryAlreadyExists {
			slog.Debug("User already in group", "userDN", userDN, "groupDN", groupDN)
			return nil
		}
		return fmt.Errorf("failed to add user %s to group %s: %w", userDN, groupDN, err)
	}

	return nil
}

func RemoveUserFromGroup(ctx context.Context, groupDN string, userDN string) error {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return fmt.Errorf("LDAP connection not found in context")
	}

	// Create a new modify request to remove the user from the group.
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)
	modifyRequest.Delete("member", []string{userDN})

	// Execute the modify request.
	if err := l.Modify(modifyRequest); err != nil {
		return fmt.Errorf("failed to remove user %s from group %s: %w", userDN, groupDN, err)
	}

	return nil
}

func UserInGroup(ctx context.Context, groupDN string, userDN string) (bool, error) {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return false, fmt.Errorf("LDAP connection not found in context")
	}

	// Create a new search request to check if the user is a member of the group.
	searchRequest := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=group)(member=%s))", ldap.EscapeFilter(userDN)),
		nil,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return false, fmt.Errorf("failed to search LDAP: %w", err)
	}

	return len(sr.Entries) > 0, nil
}

func GetGroupMemberDNs(ctx context.Context, groupDN string) ([]string, error) {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return nil, fmt.Errorf("LDAP connection not found in context")
	}

	// Create a new search request to get the members of the group.
	searchRequest := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"member"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %w", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("group %q not found", groupDN)
	}

	members := sr.Entries[0].GetAttributeValues("member")
	return members, nil
}

func GetGroupsForUser(ctx context.Context, userDN string) ([]string, error) {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return nil, fmt.Errorf("LDAP connection not found in context")
	}

	// Create a new search request to get the groups of the user.
	searchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"memberOf"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %w", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user %q not found", userDN)
	}

	groups := sr.Entries[0].GetAttributeValues("memberOf")
	return groups, nil
}

// GetGroupMemberUsernames retrieves the usernames of all members of a group.
func GetCephGroupMemberUsernames(ctx context.Context, baseDN string, groupFullName string) ([]string, error) {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return nil, fmt.Errorf("LDAP connection not found in context")
	}

	// searchRequest := ldap.NewSearchRequest(
	// 	groupDN,
	// 	ldap.ScopeBaseObject,
	// 	ldap.NeverDerefAliases,
	// 	0, 0, false,
	// 	"(objectClass=*)",
	// 	[]string{"member"},
	// 	nil,
	// )
	// Create a new search request to get the members of the group.
	fmt.Println(groupFullName)
	testDN := fmt.Sprintf("cn=%s,ou=Ceph,ou=RACS,ou=Groups,ou=IS,ou=units,dc=ad,dc=uoregon,dc=edu", groupFullName)
	searchRequest := ldap.NewSearchRequest(
		testDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"member"}, // What attributes to return
		nil,
	)
	fmt.Printf("ceph search request: %+v\n", searchRequest)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %w", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("group %q not found", baseDN)
	}

	members := sr.Entries[0].GetAttributeValues("member")
	usernames := make([]string, len(members))
	for i, member := range members {
		u, err := ConvertDNToObjectName(member)
		if err != nil {
			return nil, fmt.Errorf("failed to convert DN to username: %w", err)
		}
		usernames[i] = u
	}
	return usernames, nil
}

// GetGroupMemberUsernames retrieves the usernames of all members of a group.
func GetGroupMemberUsernames(ctx context.Context, groupDN string) ([]string, error) {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return nil, fmt.Errorf("LDAP connection not found in context")
	}

	// Create a new search request to get the members of the group.
	searchRequest := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"member"},
		nil,
	)
	fmt.Printf("norm search request: %+v\n", searchRequest)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %w", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("group %q not found", groupDN)
	}

	members := sr.Entries[0].GetAttributeValues("member")
	usernames := make([]string, len(members))
	for i, member := range members {
		u, err := ConvertDNToObjectName(member)
		if err != nil {
			return nil, fmt.Errorf("failed to convert DN to username: %w", err)
		}
		usernames[i] = u
	}
	return usernames, nil
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

func GetGroupDN(ctx context.Context, groupname string) (string, bool, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", false, fmt.Errorf("config not found in context")
	}
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return "", false, fmt.Errorf("LDAP connection not found in context")
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
			slog.Debug("Group not found", "groupname", groupname)
			return "", false, nil
		}
		slog.Error("LDAP search failed", "error", err)
		return "", false, fmt.Errorf("LDAP search failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		slog.Debug("Group not found", "groupname", groupname)
		return "", false, nil
	}

	return sr.Entries[0].DN, true, nil
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

// GetGroupNamesInOU retrieves the names of all groups in a given organizational unit (OU).
func GetGroupNamesInOU(ctx context.Context, ouDN string, recursive bool) ([]string, error) {
	var scope int

	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return nil, fmt.Errorf("LDAP connection not found in context")
	}

	if recursive {
		scope = ldap.ScopeWholeSubtree
	} else {
		scope = ldap.ScopeSingleLevel
	}

	searchRequest := ldap.NewSearchRequest(
		ouDN,
		scope,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=group)",
		[]string{"cn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %w", err)
	}

	groupNames := make([]string, len(sr.Entries))
	for i, entry := range sr.Entries {
		groupNames[i] = entry.GetAttributeValue("cn")
	}

	return groupNames, nil
}

// GetGroupDNsInOU retrieves the distinguished names (DNs) of all groups in a given organizational unit (OU).
func GetGroupDNsInOU(ctx context.Context, ouDN string) ([]string, error) {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return nil, fmt.Errorf("LDAP connection not found in context")
	}

	searchRequest := ldap.NewSearchRequest(
		ouDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=group)",
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %w", err)
	}

	groupDNs := make([]string, len(sr.Entries))
	for i, entry := range sr.Entries {
		groupDNs[i] = entry.DN
	}

	return groupDNs, nil
}

// GetOUDNsInOU retrieves the distinguished names (DNs) of all organizational units (OUs) in a given organizational unit (OU).
func getOUDNsInOU(ctx context.Context, ouDN string) ([]string, error) {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return nil, fmt.Errorf("LDAP connection not found in context")
	}

	searchRequest := ldap.NewSearchRequest(
		ouDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=organizationalUnit)",
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP: %w", err)
	}

	ouDNs := make([]string, len(sr.Entries))
	for i, entry := range sr.Entries {
		ouDNs[i] = entry.DN
	}

	return ouDNs, nil
}

// DeleteOURecursively deletes an organizational unit (OU) and all its contents.
func DeleteOURecursively(ctx context.Context, dn string) error {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return fmt.Errorf("LDAP connection not found in context")
	}

	ctrl := ldap.NewControlSubtreeDelete()
	delRequest := ldap.NewDelRequest(dn, []ldap.Control{ctrl})
	if err := l.Del(delRequest); err != nil {
		return fmt.Errorf("failed to delete OU %s: %w", dn, err)
	}

	return nil
}

// DeleteGroup deletes a group from LDAP.
func DeleteGroup(ctx context.Context, groupDN string) error {
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return fmt.Errorf("LDAP connection not found in context")
	}

	delRequest := ldap.NewDelRequest(groupDN, nil)
	if err := l.Del(delRequest); err != nil {
		return fmt.Errorf("failed to delete group %s: %w", groupDN, err)
	}

	return nil
}
