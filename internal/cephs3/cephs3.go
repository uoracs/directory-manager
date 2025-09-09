package cephs3 

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/uoracs/directory-manager/internal/config"
	"github.com/uoracs/directory-manager/internal/keys"
	ld "github.com/uoracs/directory-manager/internal/ldap"
)

var (
	err                   error
	found                 bool
	groupPrefix           = "is.racs.cephs3."
	topLevelUsersGroupDN  = "CN=IS.RACS.Talapas.Users,OU=RACS,OU=Groups,OU=IS,OU=Units,DC=ad,DC=uoregon,DC=edu"
	topLevelAdminsGroupDN = "CN=IS.RACS.Talapas.CephS3Admins,OU=RACS,OU=Groups,OU=IS,OU=Units,DC=ad,DC=uoregon,DC=edu"
)

func ConvertCEPHGroupNametoShortName(cephs3Name string) (string, error) {
	slog.Debug("Converting cephs3 group name to short name", "cephs3Name", cephs3Name)
	parts := strings.Split(cephs3Name, ".")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid cephs3 group name: %s", cephs3Name)
	}
	shortName := parts[len(parts)-1]
	slog.Debug("Converted cephs3 group name to short name", "shortName", shortName)
	return shortName, nil
}

// OwnerrgGroupNameRegex returns the regex for the cephs3 group name.
// This is used to match only the cephs3 groups in the LDAP directory,
// not the subgroups or any others.
func cephs3GroupNameRegex(ctx context.Context) (string, error) {
	// Initialize the cephs3 group name regex
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephs3GroupNameRegex := fmt.Sprintf("^%s([a-zA-Z0-9_\\-]+)$", groupPrefix)
	slog.Debug("cephs3 group name regex", "regex", cephs3GroupNameRegex)
	return cephs3GroupNameRegex, nil
}

func getcephs3FullName(ctx context.Context, cephs3Name string) (string, error) {
	slog.Debug("Getting cephs3 full name", "cephs3Name", cephs3Name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s", groupPrefix, cephs3Name)
	slog.Debug("cephs3 full name", "name", n)
	return n, nil
}

func getcephs3AdminsGroupFullName(ctx context.Context, cephs3Name string) (string, error) {
	slog.Debug("Getting cephs3 admins group full name", "cephs3Name", cephs3Name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s.admins", groupPrefix, cephs3Name)
	slog.Debug("cephs3 admins group full name", "name", n)
	return n, nil
}

func getcephs3OWNERGroupFullName(ctx context.Context, cephs3Name string) (string, error) {
	slog.Debug("Getting cephs3 OWNER group full name", "cephs3Name", cephs3Name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s.owner", groupPrefix, cephs3Name)
	slog.Debug("cephs3 OWNER group full name", "name", n)
	return n, nil
}

func getUserDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting user DN", "name", name)
	dn, err := ld.GetUserDN(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get user DN: %w", err)
	}
	if dn == "" {
		return "", fmt.Errorf("user %s not found", name)
	}
	slog.Debug("User DN", "dn", dn)
	return dn, nil
}

// getcephs3SubgroupOUDN returns the DistinguishedName of the cephs3 subgroup OU with the given name.
func getcephs3SubgroupOUDN(ctx context.Context, cephs3Name string) (string, error) {
	slog.Debug("Getting cephs3 subgroup OU DN", "cephs3Name", cephs3Name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephs3DN, err := getcephs3OUDN(ctx, cephs3Name)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	n := fmt.Sprintf("OU=Groups,%s", cephs3DN)
	slog.Debug("cephs3 subgroup OU DN", "dn", n)
	return n, nil
}

// getcephs3OUDN returns the DistinguishedName of the cephs3 OU with the given name.
// for example: OU=Ownerrg_name,OU=cephs3,DC=example,DC=com
func getcephs3OUDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting cephs3 OU DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	baseDN := cfg.LDAPCephs3DN
	n := fmt.Sprintf("OU=%s,%s", name, baseDN)
	slog.Debug("cephs3 OU DN", "dn", n)
	return n, nil
}

// getcephs3DN returns the DistinguishedName of the cephs3 with the given name.
// if not found, it returns an error.
func getcephs3DN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting cephs3 DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephs3DN, err := getcephs3OUDN(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	groupName, err := getcephs3FullName(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", groupName, cephs3DN)
	slog.Debug("cephs3 DN", "dn", n)
	return n, nil
}

// findcephs3DN returns the DistinguishedName of the cephs3 with the given name.
// includes a check if the group exists.
// if not found, it returns an empty string, false, and nil
func findcephs3DN(ctx context.Context, name string) (string, bool, error) {
	slog.Debug("Finding cephs3 DN", "name", name)
	groupName, err := getcephs3FullName(ctx, name)
	if err != nil {
		return "", false, fmt.Errorf("failed to get cephs3 full name: %w", err)
	}
	dn, found, err := ld.GetGroupDN(ctx, groupName)
	if !found && err == nil {
		slog.Debug("cephs3 not found", "name", name)
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("failed to get group DN: %w", err)
	}
	slog.Debug("cephs3 DN found", "dn", dn)
	return dn, true, nil
}

// getcephs3SubgroupShortName returns the short name of the cephs3 subgroup with the given name.
// for example: myprefix.groupname.subgroup_name -> subgroup_name
func getcephs3SubgroupShortName(cephs3Name string, subgroupName string) string {
	slog.Debug("Getting cephs3 subgroup short name", "cephs3Name", cephs3Name, "subgroupName", subgroupName)
	parts := strings.Split(subgroupName, ".")
	n := parts[len(parts)-1]
	slog.Debug("cephs3 subgroup short name", "name", n)
	return n
}

// getcephs3AdminsGroupDN returns the DistinguishedName of the cephs3 Admins group with the given name.
func getcephs3AdminsGroupDN(ctx context.Context, cephs3Name string) (string, error) {
	slog.Debug("Getting cephs3 admins group DN", "cephs3Name", cephs3Name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephs3DN, err := getcephs3OUDN(ctx, cephs3Name)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	adminsGroupFullName, err := getcephs3AdminsGroupFullName(ctx, cephs3Name)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 admins group full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", adminsGroupFullName, cephs3DN)
	slog.Debug("cephs3 admins group DN", "dn", n)
	return n, nil
}

func GetCephs3GroupGID(ctx context.Context, groupName string) (string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}

	gid, err := ld.GetGidOfExistingGroup(ctx, groupName)
	if err != nil {
		return "", fmt.Errorf("failed to get GID for group %s: %w", groupName, err)
	}

	return gid, nil
}

// getcephs3OWNERGroupDN returns the DistinguishedName of the cephs3 Owner group with the given name.
func getCephs3OWNERGroupDN(ctx context.Context, cephs3Name string) (string, error) {
	slog.Debug("Getting cephs3 Owner group DN", "cephs3Name", cephs3Name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephs3DN, err := getcephs3OUDN(ctx, cephs3Name)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	OwnerGroupFullName, err := getcephs3OWNERGroupFullName(ctx, cephs3Name)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 Owner group full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", OwnerGroupFullName, cephs3DN)
	slog.Debug("cephs3 Owner group DN", "dn", n)
	return n, nil
}

// getcephs3SubgroupDN returns the DistinguishedName of the cephs3 subgroup with the given name.
func getcephs3SubgroupDN(ctx context.Context, cephs3Name string, subgroupName string) (string, error) {
	slog.Debug("Getting cephs3 subgroup DN", "cephs3Name", cephs3Name, "subgroupName", subgroupName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephs3DN, err := getcephs3OUDN(ctx, cephs3Name)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	subgroupFullName, err := getcephs3SubgroupName(ctx, cephs3Name, subgroupName)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 subgroup full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,OU=Groups,%s", subgroupFullName, cephs3DN)
	slog.Debug("cephs3 subgroup DN", "dn", n)
	return n, nil
}

// getcephs3SubgroupName returns the name of the cephs3 subgroup with the given name.
func getcephs3SubgroupName(ctx context.Context, cephs3Name string, subgroupName string) (string, error) {
	slog.Debug("Getting cephs3 subgroup name", "cephs3Name", cephs3Name, "subgroupName", subgroupName)
	cephs3FullName, err := getcephs3FullName(ctx, cephs3Name)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 full name: %w", err)
	}
	subgroupFullName := fmt.Sprintf("%s.%s", cephs3FullName, subgroupName)
	slog.Debug("cephs3 subgroup name", "name", subgroupFullName)
	return subgroupFullName, nil
}

// getAllcephs3DNs returns all the cephs3 DNs in the LDAP directory.
func getAllcephs3DNs(ctx context.Context) ([]string, error) {
	slog.Debug("Getting all cephs3 DNs")
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	allGroupNamesIncephs3sOU, err := ld.GetGroupNamesInOU(ctx, cfg.LDAPCephs3DN, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get group names in cephs3s OU: %w", err)
	}
	cephs3GroupNameRegex, err := cephs3GroupNameRegex(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 group name regex: %w", err)
	}
	var cephs3DNs []string
	for _, groupName := range allGroupNamesIncephs3sOU {
		slog.Debug("Checking group name", "groupName", groupName)
		if matched, _ := regexp.MatchString(cephs3GroupNameRegex, groupName); matched {
			cephs3DN, found, err := ld.GetGroupDN(ctx, groupName)
			if err != nil {
				return nil, fmt.Errorf("failed to get group DN: %w", err)
			}
			if found {
				cephs3DNs = append(cephs3DNs, cephs3DN)
			}
		}
	}

	return cephs3DNs, nil
}

// addUserToTopLevelUsersGroup adds a user to the top level users group.
func addUserToTopLevelUsersGroup(ctx context.Context, member string) error {
	slog.Debug("Adding user to top level users group", "member", member)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}
	inGroup, err := ld.UserInGroup(ctx, topLevelUsersGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User already in top level users group", "userDN", userDN, "topLevelUsersGroupDN", topLevelUsersGroupDN)
		return nil
	}
	err = ld.AddUserToGroup(ctx, topLevelUsersGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to users group: %w", member, err)
	}
	slog.Debug("Added user to top level users group", "member", member)
	return nil
}

// addUserToTopLevelAdminsGroup adds a user to the top level admins group.
func addUsertoTopLevelAdminsGroup(ctx context.Context, member string) error {
	slog.Debug("Adding user to top level admins group", "member", member)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}
	inGroup, err := ld.UserInGroup(ctx, topLevelAdminsGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User already in top level admins group", "userDN", userDN, "topLevelAdminsGroupDN", topLevelAdminsGroupDN)
		return nil
	}
	err = ld.AddUserToGroup(ctx, topLevelAdminsGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to admins group: %w", member, err)
	}
	slog.Debug("Added user to top level admins group", "member", member)
	return nil
}

// removeUserFromTopLevelUsersGroup removes a user from the top level users group.
func removeUserFromTopLevelUsersGroup(ctx context.Context, member string) error {
	slog.Debug("Removing user from top level users group", "member", member)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}
	inGroup, err := ld.UserInGroup(ctx, topLevelUsersGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in top level users group", "userDN", userDN, "topLevelUsersGroupDN", topLevelUsersGroupDN)
		return nil
	}
	err = ld.RemoveUserFromGroup(ctx, topLevelUsersGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from users group: %w", member, err)
	}
	slog.Debug("Removed user from top level users group", "member", member)
	return nil
}

// removeUserFromTopLevelAdminsGroup removes a user from the top level admins group.
func removeUserFromTopLevelAdminsGroup(ctx context.Context, member string) error {
	slog.Debug("Removing user from top level admins group", "member", member)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}
	inGroup, err := ld.UserInGroup(ctx, topLevelAdminsGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in top level admins group", "userDN", userDN, "topLevelAdminsGroupDN", topLevelAdminsGroupDN)
		return nil
	}
	err = ld.RemoveUserFromGroup(ctx, topLevelAdminsGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from admins group: %w", member, err)
	}
	slog.Debug("Removed user from top level admins group", "member", member)
	return nil
}

// userInAnycephs3 checks if the user is in any cephs3.
func userInAnycephs3(ctx context.Context, username string) (bool, error) {
	slog.Debug("Checking if user is in any cephs3", "username", username)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	userDN, err := getUserDN(ctx, username)
	if err != nil {
		return false, fmt.Errorf("failed to get user DN: %w", err)
	}
	userGroups, err := ld.GetGroupsForUser(ctx, userDN)
	if err != nil {
		return false, fmt.Errorf("failed to get user groups: %w", err)
	}
	for _, groupDN := range userGroups {
		groupName, err := ld.ConvertDNToObjectName(groupDN)
		if err != nil {
			return false, fmt.Errorf("failed to convert DN to object name: %w", err)
		}
		if strings.HasPrefix(groupName, groupPrefix) {
			slog.Debug("User found in some cephs3", "userDN", userDN, "groupDN", groupDN)
			return true, nil
		}
	}
	slog.Debug("User not found in any cephs3 group")
	return false, nil
}

// userIsAdminInAnycephs3 checks if the user is an admin in any cephs3.
func userIsAdminInAnycephs3(ctx context.Context, username string) (bool, error) {
	slog.Debug("Checking if user is admin in any cephs3", "username", username)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	userDN, err := getUserDN(ctx, username)
	if err != nil {
		return false, fmt.Errorf("failed to get user DN: %w", err)
	}
	userGroups, err := ld.GetGroupsForUser(ctx, userDN)
	if err != nil {
		return false, fmt.Errorf("failed to get user groups: %w", err)
	}
	for _, groupDN := range userGroups {
		groupName, err := ld.ConvertDNToObjectName(groupDN)
		if err != nil {
			return false, fmt.Errorf("failed to convert DN to object name: %w", err)
		}
		if strings.HasPrefix(groupName, groupPrefix) {
			cephs3Name := strings.TrimPrefix(groupName, groupPrefix)
			if strings.Contains(cephs3Name, ".") {
				// this is admins,Owner, or subgroup, ignore it
				continue
			}
			cephs3AdminsGroupDN, err := getcephs3AdminsGroupDN(ctx, cephs3Name)
			if err != nil {
				return false, fmt.Errorf("failed to get cephs3 admins group DN: %w", err)
			}
			inGroup, err := ld.UserInGroup(ctx, cephs3AdminsGroupDN, userDN)
			if err != nil {
				return false, fmt.Errorf("failed to check if user is in group: %w", err)
			}
			if inGroup {
				slog.Debug("User found as admin in cephs3", "userDN", userDN, "groupDN", groupDN)
				return true, nil
			}
			continue
		}
	}
	slog.Debug("User not found as admin in any cephs3")
	return false, nil
}

// cephs3Exists checks if the cephs3 with the given name exists.
func Cephs3Exists(ctx context.Context, name string) (bool, error) {
	// Check if the cephs3 with the given name exists
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	cephs3DN, found, err := findcephs3DN(ctx, name)
	if err != nil {
		return false, fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	if !found {
		slog.Debug("cephs3 not found", "name", name)
		return false, nil
	}
	slog.Debug("cephs3 found", "name", name, "cephs3DN", cephs3DN)
	return true, nil
}

func Cephs3Create(ctx context.Context, cephs3Name string, ownerUsername string) error {
	slog.Debug("Creating cephs3", "name", cephs3Name, "owner", ownerUsername)

	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}

	// Check if the cephs3 group already exists
	cephs3DN, found, err := findcephs3DN(ctx, cephs3Name)
	if found {
		slog.Debug("cephs3 already exists", "name", cephs3Name, "cephs3DN", cephs3DN)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to find cephs3 DN: %w", err)
	}

	gidNumber, err := ld.GetNextGidNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next GID number: %w", err)
	}
	slog.Debug("GID number", "gidNumber", gidNumber)

	allcephs3DN := cfg.LDAPCephs3DN
	slog.Debug("All cephs3s DN", "allcephs3DN", allcephs3DN)

	// Create the cephs3 group OU inside the cephs3 base DN
	err = ld.CreateOU(ctx, allcephs3DN, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to create cephs3 OU: %w", err)
	}
	slog.Debug("Created cephs3 OU", "name", cephs3Name)

	// Create the cephs3 subgroups OU inside the cephs3 OU
	cephs3OUDN, err := getcephs3OUDN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	slog.Debug("cephs3 DN", "cephs3OUDN", cephs3OUDN)
	err = ld.CreateOU(ctx, cephs3OUDN, "Groups")
	if err != nil {
		return fmt.Errorf("failed to create cephs3 subgroups OU: %w", err)
	}
	slog.Debug("Created cephs3 subgroups OU", "name", cephs3Name)

	// Create the cephs3 group object
	cephs3FullName, err := getcephs3FullName(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 full name: %w", err)
	}
	slog.Debug("cephs3 group name", "cephs3Name", cephs3FullName)
	err = ld.CreateGroup(ctx, cephs3OUDN, cephs3FullName, gidNumber)
	if err != nil {
		return fmt.Errorf("failed to create cephs3 group object: %w", err)
	}
	slog.Debug("Created cephs3 group object", "cephs3Name", cephs3FullName)

	// Create the cephs3 admins group object
	cephs3AdminsGroupName, err := getcephs3AdminsGroupFullName(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 admins group full name: %w", err)
	}
	slog.Debug("cephs3 admins group name", "cephs3AdminsGroupName", cephs3AdminsGroupName)
	err = ld.CreateGroup(ctx, cephs3OUDN, cephs3AdminsGroupName, gidNumber+1)
	if err != nil {
		return fmt.Errorf("failed to create cephs3 admins group object: %w", err)
	}
	slog.Debug("Created cephs3 admins group object", "cephs3AdminsGroupName", cephs3AdminsGroupName)

	// Create the cephs3 Owner group object
	cephs3OwnerGroupFullName, err := getcephs3OWNERGroupFullName(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 OWNER group full name: %w", err)
	}
	slog.Debug("cephs3 OWNER group name", "OwnerrgOwnerGroupName", cephs3OwnerGroupFullName)
	err = ld.CreateGroup(ctx, cephs3OUDN, cephs3OwnerGroupFullName, gidNumber+2)
	if err != nil {
		return fmt.Errorf("failed to create cephs3 OWNER group object: %w", err)
	}
	slog.Debug("Created cephs3 OWNER group object", "cephs3OwnerGroupName", cephs3OwnerGroupFullName)

	// Add the Owner to the cephs3 Owner group
	err = cephs3SetOWNER(ctx, cephs3Name, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to cephs3 Owner group %s: %w", ownerUsername, cephs3Name, err)
	}
	slog.Debug("Added Owner to cephs3 Owner group", "ownerUsername", ownerUsername, "cephs3Name", cephs3Name)

	// Add the Owner to the cephs3 admins group
	err = Cephs3AddAdmin(ctx, cephs3Name, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to cephs3 admins group %s: %w", ownerUsername, cephs3Name, err)
	}
	slog.Debug("Added Owner to cephs3 admins group", "ownerUsername", ownerUsername, "cephs3Name", cephs3Name)

	// Add the Owner to the cephs3 group
	err = Cephs3AddMember(ctx, cephs3Name, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to cephs3 %s: %w", ownerUsername, cephs3Name, err)
	}
	slog.Debug("Added Owner to cephs3 group", "ownerUsername", ownerUsername, "cephs3Name", cephs3Name)

	return nil
}

// cephs3Delete deletes the cephs3 with the given name.
// It will error if there are any members in the group.
func Cephs3Delete(ctx context.Context, cephs3Name string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephOUDN, err := getcephs3OUDN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	// Check if the cephs3 exists
	cephDN, found, err := findcephs3DN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to find cephs3 DN: %w", err)
	}
	if !found {
		slog.Debug("cephs3 not found", "name", cephs3Name)
		return nil
	}
	members, err := ld.GetGroupMemberUsernames(ctx, cephDN)
	if err != nil {
		return fmt.Errorf("failed to get group members: %w", err)
	}
	if len(members) > 1 {
		return fmt.Errorf("cephs3 %s has non-Owner members, cannot delete", cephs3Name)
	}
	err = ld.DeleteOURecursively(ctx, cephOUDN)
	if err != nil {
		return fmt.Errorf("failed to delete cephs3 group object: %w", err)
	}
	return nil
}

// cephs3GetOwner returns the Owner username for the cephs3 with the given name.
func Cephs3GetOwnerUsername(ctx context.Context, cephs3Name string) (string, error) {
	// Get the Owner username for the cephs3 with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephs3OwnerGroupDN, err := getCephs3OWNERGroupDN(ctx, cephs3Name)
	if err != nil {
		return "", fmt.Errorf("failed to get cephs3 Owner group DN: %w", err)
	}
	members, err := ld.GetGroupMemberUsernames(ctx, cephs3OwnerGroupDN)
	if err != nil {
		return "", fmt.Errorf("failed to get group members: %w", err)
	}
	if len(members) == 0 {
		return "", fmt.Errorf("no Owner found for cephs3 %s", cephs3Name)
	}
	if len(members) > 1 {
		return "", fmt.Errorf("multiple Owners found for cephs3 %s", cephs3Name)
	}
	return members[0], nil
}

func cephs3SetOWNER(ctx context.Context, cephs3Name string, ownerUsername string) error {
	slog.Debug("Setting Owner for cephs3", "cephs3Name", cephs3Name, "ownerUsername", ownerUsername)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephDN, err := getcephs3DN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	ownerDN, err := getUserDN(ctx, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to get owner DN: %w", err)
	}
	// Remove existing Owner from the cephs3 Owner group
	cephs3OwnerGroupDN, err := getCephs3OWNERGroupDN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 Owner group DN: %w", err)
	}
	// find existing users in the group
	existingMemberDNs, err := ld.GetGroupMemberDNs(ctx, cephs3OwnerGroupDN)
	if err != nil {
		return fmt.Errorf("failed to get group members: %w", err)
	}
	if len(existingMemberDNs) == 0 {
		slog.Debug("No existing Owner found in cephs3 Owner group", "cephs3OwnerGroupDN", cephs3OwnerGroupDN)
	} else if len(existingMemberDNs) > 1 {
		slog.Debug("Multiple existing Owners found in cephs3 Owner group", "cephs3OwnerGroupDN", cephs3OwnerGroupDN)
	}
	for _, existingMemberDN := range existingMemberDNs {
		slog.Debug("Removing existing Owner from cephs3 Owner group", "existingMemberDN", existingMemberDN)
		err = ld.RemoveUserFromGroup(ctx, cephs3OwnerGroupDN, existingMemberDN)
		if err != nil {
			return fmt.Errorf("failed to remove existing Owner from cephs3 Owner group: %w", err)
		}
	}
	// Add the user to the cephs3
	err = ld.AddUserToGroup(ctx, cephDN, ownerDN)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to cephs3 %s: %w", ownerUsername, cephs3Name, err)
	}
	// Add the user to the cephs3 Owner group
	err = ld.AddUserToGroup(ctx, cephs3OwnerGroupDN, ownerDN)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to cephs3 Owner group %s: %w", ownerUsername, cephs3Name, err)
	}

	// Add the user to the admins group
	cephs3AdminsGroupDN, err := getcephs3AdminsGroupDN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 admins group DN: %w", err)
	}
	err = ld.AddUserToGroup(ctx, cephs3AdminsGroupDN, ownerDN)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to cephs3 admins group %s: %w", ownerUsername, cephs3Name, err)
	}

	return nil
}

func Cephs3List(ctx context.Context) ([]string, error) {
	// List all cephs3
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	allcephs3DN := cfg.LDAPCephs3DN

	slog.Debug("Allcephs3DN ", "allcephs3DN", allcephs3DN)
	cephs3, err := ld.GetGroupNamesInOU(ctx, allcephs3DN, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3: %w", err)
	}
	cephs3GroupNameRegex, err := cephs3GroupNameRegex(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 group name regex: %w", err)
	}
	var cephs3GroupNames []string
	for _, ceph := range cephs3 {
		if matched, err := regexp.MatchString(cephs3GroupNameRegex, ceph); err != nil {
			return nil, fmt.Errorf("failed to match cephs3 group name regex: %w", err)
		} else if matched {
			cephs3GroupNames = append(cephs3GroupNames, ceph)
		}
	}
	var cephs3ShortNames []string
	for _, ceph := range cephs3GroupNames {
		shortName, err := ConvertCEPHGroupNametoShortName(ceph)
		if err != nil {
			return nil, fmt.Errorf("failed to convert cephs3 group name to short name: %w", err)
		}
		cephs3ShortNames = append(cephs3ShortNames, shortName)
	}
	slices.Sort(cephs3ShortNames)
	slog.Debug("cephs3 names", "cephs3ShortNames", cephs3ShortNames)
	return cephs3ShortNames, nil
}

// cephs3AddMember adds a member to the cephs3 with the given name.
func Cephs3AddMember(ctx context.Context, cephs3Name string, member string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephs3DN, err := getcephs3DN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is already a member of the cephs3
	inGroup, err := ld.UserInGroup(ctx, cephs3DN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User already in cephs3", "userDN", userDN, "cephs3DN", cephs3DN)
		return nil
	}

	// Add the user to the cephs3 group
	slog.Debug("Adding user to cephs3", "userDN", userDN, "cephs3DN", cephs3DN)
	err = ld.AddUserToGroup(ctx, cephs3DN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to cephs3 %s: %w", member, cephs3Name, err)
	}
	slog.Debug("Added user to cephs3", "userDN", userDN, "cephs3DN", cephs3DN)

	// Add the user to the top level users group
	err = addUserToTopLevelUsersGroup(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to add user %s to top level users group: %w", member, err)
	}

	return nil
}

// cephs3RemoveMember removes a member from the cephs3 with the given name.
//
// It will remove them from the cephs3 group, all subgroups, the admin group, and the Owner group.
// If the user is not a member of any other cephs3s, they will also be removed from the top level users and admins groups.
func Cephs3RemoveMember(ctx context.Context, name string, member string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephs3DN, err := getcephs3DN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is a member of the cephs3
	inGroup, err := ld.UserInGroup(ctx, cephs3DN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in cephs3", "userDN", userDN, "cephs3DN", cephs3DN)
		return nil
	}

	// Check if the user is the Owner of the cephs3
	cephs3OWNERGroupDN, err := getCephs3OWNERGroupDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 Owner group DN: %w", err)
	}
	inGroup, err = ld.UserInGroup(ctx, cephs3OWNERGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	// if user is Owner, error
	if inGroup {
		return fmt.Errorf("user %s is the Owner of cephs3 %s, cannot remove without setting a new Owner", member, name)
	}

	// Remove the user from the cephs3 group
	err = ld.RemoveUserFromGroup(ctx, cephs3DN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from cephs3 %s: %w", member, name, err)
	}
	slog.Debug("Removed user from cephs3", "userDN", userDN, "cephs3DN", cephs3DN)

	// Remove the user from all subgroups of the cephs3
	slog.Debug("Removing user from cephs3 subgroups", "userDN", userDN)
	cephs3SubgroupOUDN, err := getcephs3SubgroupOUDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 subgroup OU DN: %w", err)
	}
	subgroups, err := ld.GetGroupDNsInOU(ctx, cephs3SubgroupOUDN)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 subgroups: %w", err)
	}
	for _, subgroupDN := range subgroups {
		slog.Debug("Checking if user is in subgroup", "subgroupDN", subgroupDN, "userDN", userDN)
		inGroup, err := ld.UserInGroup(ctx, subgroupDN, userDN)
		if err != nil {
			return fmt.Errorf("failed to check if user is in group: %w", err)
		}
		if !inGroup {
			slog.Debug("User not in subgroup", "subgroupDN", subgroupDN, "userDN", userDN)
			continue
		}
		slog.Debug("Removing user from subgroup", "subgroupDN", subgroupDN, "userDN", userDN)
		err = ld.RemoveUserFromGroup(ctx, subgroupDN, userDN)
		if err != nil {
			return fmt.Errorf("failed to remove user %s from cephs3  subgroup %s: %w", member, subgroupDN, err)
		}
		slog.Debug("Removed user from subgroup", "subgroupDN", subgroupDN, "userDN", userDN)
	}

	// Remove the user from the cephs3 Admins group if they're an admin
	cephs3AdminsGroupDN, err := getcephs3AdminsGroupDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3  admins group DN: %w", err)
	}
	inGroup, err = ld.UserInGroup(ctx, cephs3AdminsGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User is an admin, removing from cephs3 admins group", "userDN", userDN, "cephs3AdminsGroupDN", cephs3AdminsGroupDN)
		err = ld.RemoveUserFromGroup(ctx, cephs3AdminsGroupDN, userDN)
		if err != nil {
			return fmt.Errorf("failed to remove user %s from cephs3 admins group %s: %w", member, name, err)
		}
		slog.Debug("Removed user from cephs3 admins group", "userDN", userDN, "OwnerrgAdminsGroupDN", cephs3AdminsGroupDN)
	}

	// Remove the user from the cephs3 Owner group if they're a Owner
	cephs3OWNERGroupDN, err = getCephs3OWNERGroupDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 OWNER group DN: %w", err)
	}
	inGroup, err = ld.UserInGroup(ctx, cephs3OWNERGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User is a OWNER, removing from cephs3 OWNER group", "userDN", userDN, "cephs3OwnerGroupDN", cephs3OWNERGroupDN)
		err = ld.RemoveUserFromGroup(ctx, cephs3OWNERGroupDN, userDN)
		if err != nil {
			return fmt.Errorf("failed to remove user %s from cephs3 Owner group %s: %w", member, name, err)
		}
		slog.Debug("Removed user from cephs3 Owner group", "userDN", userDN, "cephs3OwnerGroupDN", cephs3OWNERGroupDN)
	}

	// // Remove the user from the top level admins group if they are not an admin in any other cephs3
	// adminInAnycephs3, err := userIsAdminInAnycephs3(ctx, member)
	// if err != nil {
	// 	return fmt.Errorf("failed to check if user is admin in any cephs3: %w", err)
	// }
	// if !adminInAnycephs3 {
	// 	err = removeUserFromTopLevelAdminsGroup(ctx, member)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to remove user %s from top level admins group: %w", member, err)
	// 	}
	// } else {
	// 	slog.Debug("User still an admin in another cephs3, not removing from top level admin group", "userDN", userDN)
	// }
	//
	// // Remove the user from the top level users group if they are not in any other cephs3
	// inAnycephs3, err := userInAnycephs3(ctx, member)
	// if err != nil {
	// 	return fmt.Errorf("failed to check if user is in any cephs3: %w", err)
	// }
	// if !inAnycephs3 {
	// 	err = removeUserFromTopLevelUsersGroup(ctx, member)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to remove user %s from top level users group: %w", member, err)
	// 	}
	// } else {
	// 	slog.Debug("User still in another cephs3, not removing from top level user group", "userDN", userDN)
	// }
	return nil
}

func Cephs3ListMemberUsernames(ctx context.Context, name string) ([]string, error) {
	// List all members of the cephs3 with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephs3DN, err := getcephs3DN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	members, err := ld.GetGroupMemberUsernames(ctx, cephs3DN)

	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// cephs3ListMemberDNs lists all member DNs of the cephs3 with the given name.
func Cephs3ListMemberDNs(ctx context.Context, name string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephs3DN, err := getcephs3DN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	members, err := ld.GetGroupMemberDNs(ctx, cephs3DN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// cephs3ListAdminUsernames lists all admin usernames of the cephs3 with the given name.
func Cephs3ListAdminUsernames(ctx context.Context, name string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephs3DN, err := getcephs3AdminsGroupDN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	admins, err := ld.GetGroupMemberUsernames(ctx, cephs3DN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(admins)
	return admins, nil
}

// cephs3AddAdmin adds an admin to the cephs3 with the given name.
func Cephs3AddAdmin(ctx context.Context, cephs3Name string, adminUsername string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	adminGroupDN, err := getcephs3AdminsGroupDN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 admin group DN: %w", err)
	}
	userDN, err := getUserDN(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the cephs3 group exists
	cephs3DN, found, err := findcephs3DN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to find cephs3 DN: %w", err)
	}
	if !found {
		slog.Debug("cephs3 not found", "name", cephs3Name)
		return fmt.Errorf("cephs3 %s not found", cephs3Name)
	}

	// Check if the user is a member of the cephs3 group
	incephs3, err := ld.UserInGroup(ctx, cephs3DN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !incephs3 {
		slog.Debug("User not in cephs3", "userDN", userDN, "cephs3DN", cephs3DN)
		return fmt.Errorf("user %s is not a member of cephs3 %s", adminUsername, cephs3Name)
	}

	// Check if the user is already an admin of the cephs3 group
	inAdminsGroup, err := ld.UserInGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inAdminsGroup {
		slog.Debug("User already in cephs3 admins group", "userDN", userDN, "cephs3DN", adminGroupDN)
		return nil
	}

	// Add the user to the cephs3 admins group
	err = ld.AddUserToGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add admin %s to cephs3 %s: %w", adminUsername, cephs3Name, err)
	}
	slog.Debug("Added admin to cephs3", "userDN", userDN, "cephs3DN", adminGroupDN)

	// Add the user to the top level admins group
	err = addUsertoTopLevelAdminsGroup(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to add admin %s to top level admins group: %w", adminUsername, err)
	}

	return nil
}

// cephs3RemoveAdmin removes an admin from the cephs3 with the given name.
func Cephs3RemoveAdmin(ctx context.Context, cephs3Name string, adminUsername string) error {
	// Remove an admin from the cephs3 with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	adminGroupDN, err := getcephs3AdminsGroupDN(ctx, cephs3Name)
	if err != nil { 
		return fmt.Errorf("failed to get cephs3 admin group DN: %w", err)
	}
	userDN, err := getUserDN(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is an admin of the cephs3
	inGroup, err := ld.UserInGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in cephs3 admins group", "userDN", userDN, "cephs3DN", adminGroupDN)
		return nil
	}

	// Remove the user from the cephs3 admins group
	err = ld.RemoveUserFromGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove admin %s from cephs3 %s: %w", adminUsername, cephs3Name, err)
	}
	slog.Debug("Removed admin from cephs3", "userDN", userDN, "cephs3DN", adminGroupDN)

	// Remove the user from the top level admins if they are not an admin of any other cephs3
	isAdminInAnothercephs3, err := userIsAdminInAnycephs3(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to check if user is admin in any cephs3: %w", err)
	}
	if !isAdminInAnothercephs3 {
		err = removeUserFromTopLevelAdminsGroup(ctx, adminUsername)
		if err != nil {
			return fmt.Errorf("failed to remove admin %s from top level admins group: %w", adminUsername, err)
		}
	} else {
		slog.Debug("User still an admin in another cephs3, not removing from top level admins group", "userDN", userDN)
	}

	return nil
}

// cephs3SubgroupExists checks if the subgroup with the given name exists under the cephs3.
func Cephs3SubgroupExists(ctx context.Context, cephs3Name string, subgroupName string) (bool, error) {
	// Check if the subgroup with the given name exists under the cephs3
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getcephs3SubgroupDN(ctx, cephs3Name, subgroupName)
	if err != nil {
		return false, fmt.Errorf("failed to get cephs3 subgroup DN: %w", err)
	}
	exists, err := ld.DNExists(ctx, subgroupDN)
	if err != nil {
		return false, fmt.Errorf("failed to check if group exists: %w", err)
	}
	return exists, nil
}

// cephs3SubgroupList lists all subgroups of the cephs3 with the given name.
func Cephs3SubgroupList(ctx context.Context, cephs3Name string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	OwnerrgSubgroupsOUDN, err := getcephs3SubgroupOUDN(ctx, cephs3Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 subgroup OU DN: %w", err)
	}
	subgroups, err := ld.GetGroupNamesInOU(ctx, OwnerrgSubgroupsOUDN, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 subgroups: %w", err)
	}
	shortNames := make([]string, len(subgroups))
	for i, subgroup := range subgroups {
		shortNames[i] = getcephs3SubgroupShortName(cephs3Name, subgroup)
	}
	slices.Sort(shortNames)
	return shortNames, nil
}

// cephs3SubgroupCreate creates a new subgroup under the cephs3 with the given name.
func Cephs3SubgroupCreate(ctx context.Context, cephs3Name string, subgroupName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getcephs3SubgroupDN(ctx, cephs3Name, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 subgroup DN: %w", err)
	}
	subgroupOUDN, err := getcephs3SubgroupOUDN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 subgroup OU DN: %w", err)
	}

	subgroupFullName, err := getcephs3SubgroupName(ctx, cephs3Name, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 subgroup full name: %w", err)
	}

	// Create the subgroup object inside the cephs3 OU/Groups
	gidNumber, err := ld.GetNextGidNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next GID number: %w", err)
	}
	err = ld.CreateGroup(ctx, subgroupOUDN, subgroupFullName, gidNumber)
	if err != nil {
		return fmt.Errorf("failed to create cephs3 subgroup object: %w", err)
	}
	slog.Debug("Created cephs3 subgroup object", "subgroupDN", subgroupDN)

	return nil
}

// cephs3SubgroupDelete deletes the subgroup with the given name under the cephs3 groups OU.
// If the subgroup is found, it returns true and nil.
func Cephs3SubgroupDelete(ctx context.Context, cephs3Name string, subgroupName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getcephs3SubgroupDN(ctx, cephs3Name, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 subgroup DN: %w", err)
	}

	// Check if the subgroup exists
	exists, err := ld.DNExists(ctx, subgroupDN)
	if err != nil {
		return fmt.Errorf("failed to check if group exists: %w", err)
	}
	if !exists {
		slog.Debug("cephs3 subgroup does not exist", "subgroupDN", subgroupDN)
		return nil
	}

	// Delete the subgroup object
	err = ld.DeleteGroup(ctx, subgroupDN)
	if err != nil {
		return fmt.Errorf("failed to delete cephs3 subgroup object: %w", err)
	}
	slog.Debug("Deleted cephs3 subgroup object", "subgroupDN", subgroupDN)

	return nil
}

// cephs3SubgroupListMemberUsernames lists all members of the subgroup with the given name under the cephs3.
func Cephs3SubgroupListMemberUsernames(ctx context.Context, cephs3Name string, subgroupName string) ([]string, error) {
	// List all members of the subgroup with the given name under the cephs3
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getcephs3SubgroupDN(ctx, cephs3Name, subgroupName)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 subgroup DN: %w", err)
	}
	// Check if the subgroup exists
	exists, err := ld.DNExists(ctx, subgroupDN)
	if err != nil {
		return nil, fmt.Errorf("failed to check if group exists: %w", err)
	}
	if !exists {
		return []string{}, nil
	}
	members, err := ld.GetGroupMemberUsernames(ctx, subgroupDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// cephs3SubgroupListMemberDNs lists all members of the subgroup with the given name under the cephs3.
func Cephs3SubgroupListMemberDNs(ctx context.Context, cephs3Name string, subgroupName string) ([]string, error) {
	// List all members of the subgroup with the given name under the cephs3
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getcephs3SubgroupDN(ctx, cephs3Name, subgroupName)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 subgroup DN: %w", err)
	}
	members, err := ld.GetGroupMemberDNs(ctx, subgroupDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// cephs3SubgroupAddMember adds a member to the subgroup with the given name under the cephs3.
func Cephs3SubgroupAddMember(ctx context.Context, cephs3Name string, subgroupName string, memberUsername string) error {
	// Check if memberUsername is in the cephs3
	cephs3DN, err := getcephs3DN(ctx, cephs3Name)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	userDN, err := getUserDN(ctx, memberUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}
	inGroup, err := ld.UserInGroup(ctx, cephs3DN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		return fmt.Errorf("user %s is not a member of the cephs3 %s", memberUsername, cephs3Name)
	}

	// Add a member to the subgroup with the given name under the cephs3
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getcephs3SubgroupDN(ctx, cephs3Name, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 subgroup DN: %w", err)
	}
	userDN, err = getUserDN(ctx, memberUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is already a member of the subgroup
	inGroup, err = ld.UserInGroup(ctx, subgroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User already in cephs3 subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
		return nil
	}

	// Add the user to the subgroup group
	err = ld.AddUserToGroup(ctx, subgroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to cephs3 subgroup %s: %w", memberUsername, subgroupName, err)
	}
	slog.Debug("Added user to cephs3 subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
	return nil
}

// cephs3SubgroupRemoveMember removes a member from the subgroup with the given name under the cephs3.
func Cephs3SubgroupRemoveMember(ctx context.Context, cephs3Name string, subgroupName string, memberUsername string) error {
	// Remove a member from the subgroup with the given name under the cephs3
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getcephs3SubgroupDN(ctx, cephs3Name, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get cephs3 subgroup DN: %w", err)
	}
	userDN, err := getUserDN(ctx, memberUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is a member of the subgroup
	inGroup, err := ld.UserInGroup(ctx, subgroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in cephs3 subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
		return nil
	}

	// Remove the user from the subgroup group
	err = ld.RemoveUserFromGroup(ctx, subgroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from cephs3 subgroup %s: %w", memberUsername, subgroupName, err)
	}
	slog.Debug("Removed user from cephs3 subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
	return nil
}

// cephs3SubgroupListNames lists all subgroup names of the cephs3 with the given name.
func Cephs3SubgroupListNames(ctx context.Context, cephs3Name string) ([]string, error) {
	// List all subgroups of the cephs3 with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephs3OUDN, err := getcephs3OUDN(ctx, cephs3Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	subgroupsDN := fmt.Sprintf("OU=Groups,%s", cephs3OUDN)
	subgroups, err := ld.GetGroupNamesInOU(ctx, subgroupsDN, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 subgroups: %w", err)
	}
	slices.Sort(subgroups)
	return subgroups, nil
}

// cephs3SubgroupListDNs lists all subgroup DNs of the cephs3 with the given name.
func Cephs3SubgroupListDNs(ctx context.Context, cephs3Name string) ([]string, error) {
	// List all subgroups of the cephs3 with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephs3OUDN, err := getcephs3OUDN(ctx, cephs3Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 DN: %w", err)
	}
	subgroupsDN := fmt.Sprintf("OU=Groups,%s", cephs3OUDN)
	subgroups, err := ld.GetGroupDNsInOU(ctx, subgroupsDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephs3 subgroups: %w", err)
	}
	slices.Sort(subgroups)
	return subgroups, nil
}
