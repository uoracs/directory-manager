package cephfs 

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
	groupPrefix           = "is.racs.cephfs."
	topLevelUsersGroupDN  = "CN=IS.RACS.Talapas.Users,OU=RACS,OU=Groups,OU=IS,OU=Units,DC=ad,DC=uoregon,DC=edu"
	topLevelAdminsGroupDN = "CN=IS.RACS.Talapas.CephAdmins,OU=RACS,OU=Groups,OU=IS,OU=Units,DC=ad,DC=uoregon,DC=edu"
)

func ConvertCEPHGroupNametoShortName(cephfsName string) (string, error) {
	slog.Debug("Converting CEPHFS group name to short name", "cephfsName", cephfsName)
	parts := strings.Split(cephfsName, ".")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid CEPHFS group name: %s", cephfsName)
	}
	shortName := parts[len(parts)-1]
	slog.Debug("Converted CEPHFS group name to short name", "shortName", shortName)
	return shortName, nil
}

// OwnerrgGroupNameRegex returns the regex for the CEPHFS group name.
// This is used to match only the CEPHFS groups in the LDAP directory,
// not the subgroups or any others.
func cephfsGroupNameRegex(ctx context.Context) (string, error) {
	// Initialize the CEPHFS group name regex
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsGroupNameRegex := fmt.Sprintf("^%s([a-zA-Z0-9_\\-]+)$", groupPrefix)
	slog.Debug("CEPHFS group name regex", "regex", cephfsGroupNameRegex)
	return cephfsGroupNameRegex, nil
}

func getCEPHFSFullName(ctx context.Context, cephfsName string) (string, error) {
	slog.Debug("Getting CEPHFS full name", "cephfsName", cephfsName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s", groupPrefix, cephfsName)
	slog.Debug("CEPHFS full name", "name", n)
	return n, nil
}

func getCEPHFSAdminsGroupFullName(ctx context.Context, cephfsName string) (string, error) {
	slog.Debug("Getting CEPHFS admins group full name", "cephfsName", cephfsName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s.admins", groupPrefix, cephfsName)
	slog.Debug("CEPHFS admins group full name", "name", n)
	return n, nil
}

func getCEPHFSOWNERGroupFullName(ctx context.Context, cephfsName string) (string, error) {
	slog.Debug("Getting CEPHFS OWNER group full name", "cephfsName", cephfsName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s.owner", groupPrefix, cephfsName)
	slog.Debug("CEPHFS OWNER group full name", "name", n)
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

// getCEPHFSSubgroupOUDN returns the DistinguishedName of the CEPHFS subgroup OU with the given name.
func getCEPHFSSubgroupOUDN(ctx context.Context, cephfsName string) (string, error) {
	slog.Debug("Getting CEPHFS subgroup OU DN", "cephfsName", cephfsName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	n := fmt.Sprintf("OU=Groups,%s", cephfsDN)
	slog.Debug("CEPHFS subgroup OU DN", "dn", n)
	return n, nil
}

// getCEPHFSOUDN returns the DistinguishedName of the CEPHFS OU with the given name.
// for example: OU=Ownerrg_name,OU=CEPHFS,DC=example,DC=com
func getCEPHFSOUDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting CEPHFS OU DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	baseDN := cfg.LDAPCephfsDN
	n := fmt.Sprintf("OU=%s,%s", name, baseDN)
	slog.Debug("CEPHFS OU DN", "dn", n)
	return n, nil
}

// getCEPHFSDN returns the DistinguishedName of the CEPHFS with the given name.
// if not found, it returns an error.
func getCEPHFSDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting CEPHFS DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSOUDN(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	groupName, err := getCEPHFSFullName(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", groupName, cephfsDN)
	slog.Debug("CEPHFS DN", "dn", n)
	return n, nil
}

// findCEPHFSDN returns the DistinguishedName of the CEPHFS with the given name.
// includes a check if the group exists.
// if not found, it returns an empty string, false, and nil
func findCEPHFSDN(ctx context.Context, name string) (string, bool, error) {
	slog.Debug("Finding CEPHFS DN", "name", name)
	groupName, err := getCEPHFSFullName(ctx, name)
	if err != nil {
		return "", false, fmt.Errorf("failed to get CEPHFS full name: %w", err)
	}
	dn, found, err := ld.GetGroupDN(ctx, groupName)
	if !found && err == nil {
		slog.Debug("CEPHFS not found", "name", name)
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("failed to get group DN: %w", err)
	}
	slog.Debug("CEPHFS DN found", "dn", dn)
	return dn, true, nil
}

// getCEPHFSSubgroupShortName returns the short name of the CEPHFS subgroup with the given name.
// for example: myprefix.groupname.subgroup_name -> subgroup_name
func getCEPHFSSubgroupShortName(cephfsName string, subgroupName string) string {
	slog.Debug("Getting CEPHFS subgroup short name", "cephfsName", cephfsName, "subgroupName", subgroupName)
	parts := strings.Split(subgroupName, ".")
	n := parts[len(parts)-1]
	slog.Debug("CEPHFS subgroup short name", "name", n)
	return n
}

// getCEPHFSAdminsGroupDN returns the DistinguishedName of the CEPHFS Admins group with the given name.
func getCEPHFSAdminsGroupDN(ctx context.Context, cephfsName string) (string, error) {
	slog.Debug("Getting CEPHFS admins group DN", "cephfsName", cephfsName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	adminsGroupFullName, err := getCEPHFSAdminsGroupFullName(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS admins group full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", adminsGroupFullName, cephfsDN)
	slog.Debug("CEPHFS admins group DN", "dn", n)
	return n, nil
}

func GetCephfsGroupGID(ctx context.Context, groupName string) (string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}

	fullCN := groupPrefix + groupName // e.g., "is.racs.cephfs.flopezlab"
	gid, err := ld.GetGidOfExistingGroup(ctx, fullCN)
	if err != nil {
		return "", fmt.Errorf("failed to get GID for group %s: %w", fullCN, err)
	}

	return gid, nil
}

// getCEPHFSOWNERGroupDN returns the DistinguishedName of the CEPHFS Owner group with the given name.
func getCEPHFSOWNERGroupDN(ctx context.Context, cephfsName string) (string, error) {
	slog.Debug("Getting CEPHFS Owner group DN", "cephfsName", cephfsName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	OwnerGroupFullName, err := getCEPHFSOWNERGroupFullName(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS Owner group full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", OwnerGroupFullName, cephfsDN)
	slog.Debug("CEPHFS Owner group DN", "dn", n)
	return n, nil
}

// getCEPHFSSubgroupDN returns the DistinguishedName of the CEPHFS subgroup with the given name.
func getCEPHFSSubgroupDN(ctx context.Context, cephfsName string, subgroupName string) (string, error) {
	slog.Debug("Getting CEPHFS subgroup DN", "cephfsName", cephfsName, "subgroupName", subgroupName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	subgroupFullName, err := getCEPHFSSubgroupName(ctx, cephfsName, subgroupName)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS subgroup full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,OU=Groups,%s", subgroupFullName, cephfsDN)
	slog.Debug("CEPHFS subgroup DN", "dn", n)
	return n, nil
}

// getCEPHFSSubgroupName returns the name of the CEPHFS subgroup with the given name.
func getCEPHFSSubgroupName(ctx context.Context, cephfsName string, subgroupName string) (string, error) {
	slog.Debug("Getting CEPHFS subgroup name", "cephfsName", cephfsName, "subgroupName", subgroupName)
	cephfsFullName, err := getCEPHFSFullName(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS full name: %w", err)
	}
	subgroupFullName := fmt.Sprintf("%s.%s", cephfsFullName, subgroupName)
	slog.Debug("CEPHFS subgroup name", "name", subgroupFullName)
	return subgroupFullName, nil
}

// getAllCEPHFSDNs returns all the CEPHFS DNs in the LDAP directory.
func getAllCEPHFSDNs(ctx context.Context) ([]string, error) {
	slog.Debug("Getting all CEPHFS DNs")
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	allGroupNamesInCEPHFSsOU, err := ld.GetGroupNamesInOU(ctx, cfg.LDAPCephfsDN, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get group names in CEPHFSs OU: %w", err)
	}
	cephfsGroupNameRegex, err := cephfsGroupNameRegex(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS group name regex: %w", err)
	}
	var cephfsDNs []string
	for _, groupName := range allGroupNamesInCEPHFSsOU {
		slog.Debug("Checking group name", "groupName", groupName)
		if matched, _ := regexp.MatchString(cephfsGroupNameRegex, groupName); matched {
			cephfsDN, found, err := ld.GetGroupDN(ctx, groupName)
			if err != nil {
				return nil, fmt.Errorf("failed to get group DN: %w", err)
			}
			if found {
				cephfsDNs = append(cephfsDNs, cephfsDN)
			}
		}
	}

	return cephfsDNs, nil
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

// userInAnyCEPHFS checks if the user is in any CEPHFS.
func userInAnyCEPHFS(ctx context.Context, username string) (bool, error) {
	slog.Debug("Checking if user is in any CEPHFS", "username", username)
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
			slog.Debug("User found in some CEPHFS", "userDN", userDN, "groupDN", groupDN)
			return true, nil
		}
	}
	slog.Debug("User not found in any CEPHFS group")
	return false, nil
}

// userIsAdminInAnyCEPHFS checks if the user is an admin in any CEPHFS.
func userIsAdminInAnyCEPHFS(ctx context.Context, username string) (bool, error) {
	slog.Debug("Checking if user is admin in any CEPHFS", "username", username)
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
			cephfsName := strings.TrimPrefix(groupName, groupPrefix)
			if strings.Contains(cephfsName, ".") {
				// this is admins,Owner, or subgroup, ignore it
				continue
			}
			cephfsAdminsGroupDN, err := getCEPHFSAdminsGroupDN(ctx, cephfsName)
			if err != nil {
				return false, fmt.Errorf("failed to get CEPHFS admins group DN: %w", err)
			}
			inGroup, err := ld.UserInGroup(ctx, cephfsAdminsGroupDN, userDN)
			if err != nil {
				return false, fmt.Errorf("failed to check if user is in group: %w", err)
			}
			if inGroup {
				slog.Debug("User found as admin in CEPHFS", "userDN", userDN, "groupDN", groupDN)
				return true, nil
			}
			continue
		}
	}
	slog.Debug("User not found as admin in any CEPHFS")
	return false, nil
}

// CephfsExists checks if the CEPHFS with the given name exists.
func CephfsExists(ctx context.Context, name string) (bool, error) {
	// Check if the CEPHFS with the given name exists
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	cephfsDN, found, err := findCEPHFSDN(ctx, name)
	if err != nil {
		return false, fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	if !found {
		slog.Debug("CEPHFS not found", "name", name)
		return false, nil
	}
	slog.Debug("CEPHFS found", "name", name, "cephfsDN", cephfsDN)
	return true, nil
}

func CephfsCreate(ctx context.Context, cephfsName string, ownerUsername string) error {
	slog.Debug("Creating CEPHFS", "name", cephfsName, "owner", ownerUsername)

	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}

	// Check if the CEPHFS group already exists
	cephfsDN, found, err := findCEPHFSDN(ctx, cephfsName)
	if found {
		slog.Debug("CEPHFS already exists", "name", cephfsName, "cephfsDN", cephfsDN)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to find CEPHFS DN: %w", err)
	}

	// Get the starting gidNumber, we'll increment locally
	// for each group we create
	// TODO: use the prod version: ld.GetNextGidNumber
	gidNumber, err := ld.GetNextGidNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next GID number: %w", err)
	}
	slog.Debug("GID number", "gidNumber", gidNumber)

	allCephfsDN := cfg.LDAPCephfsDN
	slog.Debug("All CEPHFSs DN", "allCephfsDN", allCephfsDN)

	// Create the CEPHFS group OU inside the CEPHFS base DN
	err = ld.CreateOU(ctx, allCephfsDN, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to create CEPHFS OU: %w", err)
	}
	slog.Debug("Created CEPHFS OU", "name", cephfsName)

	// Create the CEPHFS subgroups OU inside the CEPHFS OU
	cephfsOUDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	slog.Debug("CEPHFS DN", "cephfsOUDN", cephfsOUDN)
	err = ld.CreateOU(ctx, cephfsOUDN, "Groups")
	if err != nil {
		return fmt.Errorf("failed to create CEPHFS subgroups OU: %w", err)
	}
	slog.Debug("Created CEPHFS subgroups OU", "name", cephfsName)

	// Create the CEPHFS group object
	cephfsFullName, err := getCEPHFSFullName(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS full name: %w", err)
	}
	slog.Debug("CEPHFS group name", "cephfsName", cephfsFullName)
	err = ld.CreateGroup(ctx, cephfsOUDN, cephfsFullName, gidNumber)
	if err != nil {
		return fmt.Errorf("failed to create CEPHFS group object: %w", err)
	}
	slog.Debug("Created CEPHFS group object", "cephfsName", cephfsFullName)

	// Create the CEPHFS admins group object
	cephfsAdminsGroupName, err := getCEPHFSAdminsGroupFullName(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS admins group full name: %w", err)
	}
	slog.Debug("CEPHFS admins group name", "cephfsAdminsGroupName", cephfsAdminsGroupName)
	err = ld.CreateGroup(ctx, cephfsOUDN, cephfsAdminsGroupName, gidNumber+1)
	if err != nil {
		return fmt.Errorf("failed to create CEPHFS admins group object: %w", err)
	}
	slog.Debug("Created CEPHFS admins group object", "cephfsAdminsGroupName", cephfsAdminsGroupName)

	// Create the CEPHFS Owner group object
	cephfsOwnerGroupFullName, err := getCEPHFSOWNERGroupFullName(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS OWNER group full name: %w", err)
	}
	slog.Debug("CEPHFS OWNER group name", "OwnerrgOwnerGroupName", cephfsOwnerGroupFullName)
	err = ld.CreateGroup(ctx, cephfsOUDN, cephfsOwnerGroupFullName, gidNumber+2)
	if err != nil {
		return fmt.Errorf("failed to create CEPHFS OWNER group object: %w", err)
	}
	slog.Debug("Created CEPHFS OWNER group object", "cephfsOwnerGroupName", cephfsOwnerGroupFullName)

	// Add the Owner to the CEPHFS Owner group
	err = CEPHFSSetOWNER(ctx, cephfsName, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to CEPHFS Owner group %s: %w", ownerUsername, cephfsName, err)
	}
	slog.Debug("Added Owner to CEPHFS Owner group", "ownerUsername", ownerUsername, "cephfsName", cephfsName)

	// Add the Owner to the CEPHFS admins group
	err = CephfsAddAdmin(ctx, cephfsName, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to CEPHFS admins group %s: %w", ownerUsername, cephfsName, err)
	}
	slog.Debug("Added Owner to CEPHFS admins group", "ownerUsername", ownerUsername, "cephfsName", cephfsName)

	// Add the Owner to the CEPHFS group
	err = CephfsAddMember(ctx, cephfsName, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to CEPHFS %s: %w", ownerUsername, cephfsName, err)
	}
	slog.Debug("Added Owner to CEPHFS group", "ownerUsername", ownerUsername, "cephfsName", cephfsName)

	return nil
}

// CephfsDelete deletes the CEPHFS with the given name.
// It will error if there are any members in the group.
func CephfsDelete(ctx context.Context, cephfsName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephOUDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	// Check if the CEPHFS exists
	cephDN, found, err := findCEPHFSDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to find CEPHFS DN: %w", err)
	}
	if !found {
		slog.Debug("CEPHFS not found", "name", cephfsName)
		return nil
	}
	members, err := ld.GetGroupMemberUsernames(ctx, cephDN)
	if err != nil {
		return fmt.Errorf("failed to get group members: %w", err)
	}
	if len(members) > 1 {
		return fmt.Errorf("CEPHFS %s has non-Owner members, cannot delete", cephfsName)
	}
	err = ld.DeleteOURecursively(ctx, cephOUDN)
	if err != nil {
		return fmt.Errorf("failed to delete CEPHFS group object: %w", err)
	}
	return nil
}

// CephfsGetOwner returns the Owner username for the CEPHFS with the given name.
func CephfsGetOwnerUsername(ctx context.Context, cephfsName string) (string, error) {
	// Get the Owner username for the CEPHFS with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsOwnerGroupDN, err := getCEPHFSOWNERGroupDN(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPHFS Owner group DN: %w", err)
	}
	members, err := ld.GetGroupMemberUsernames(ctx, cephfsOwnerGroupDN)
	if err != nil {
		return "", fmt.Errorf("failed to get group members: %w", err)
	}
	if len(members) == 0 {
		return "", fmt.Errorf("no Owner found for CEPHFS %s", cephfsName)
	}
	if len(members) > 1 {
		return "", fmt.Errorf("multiple Owners found for CEPHFS %s", cephfsName)
	}
	return members[0], nil
}

func CEPHFSSetOWNER(ctx context.Context, cephfsName string, ownerUsername string) error {
	slog.Debug("Setting Owner for CEPHFS", "cephfsName", cephfsName, "ownerUsername", ownerUsername)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephDN, err := getCEPHFSDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	ownerDN, err := getUserDN(ctx, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to get owner DN: %w", err)
	}
	// Remove existing Owner from the CEPHFS Owner group
	cephfsOwnerGroupDN, err := getCEPHFSOWNERGroupDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS Owner group DN: %w", err)
	}
	// find existing users in the group
	existingMemberDNs, err := ld.GetGroupMemberDNs(ctx, cephfsOwnerGroupDN)
	if err != nil {
		return fmt.Errorf("failed to get group members: %w", err)
	}
	if len(existingMemberDNs) == 0 {
		slog.Debug("No existing Owner found in CEPHFS Owner group", "cephfsOwnerGroupDN", cephfsOwnerGroupDN)
	} else if len(existingMemberDNs) > 1 {
		slog.Debug("Multiple existing Owners found in CEPHFS Owner group", "cephfsOwnerGroupDN", cephfsOwnerGroupDN)
	}
	for _, existingMemberDN := range existingMemberDNs {
		slog.Debug("Removing existing Owner from CEPHFS Owner group", "existingMemberDN", existingMemberDN)
		err = ld.RemoveUserFromGroup(ctx, cephfsOwnerGroupDN, existingMemberDN)
		if err != nil {
			return fmt.Errorf("failed to remove existing Owner from CEPHFS Owner group: %w", err)
		}
	}
	// Add the user to the CEPHFS
	err = ld.AddUserToGroup(ctx, cephDN, ownerDN)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to CEPHFS %s: %w", ownerUsername, cephfsName, err)
	}
	// Add the user to the CEPHFS Owner group
	err = ld.AddUserToGroup(ctx, cephfsOwnerGroupDN, ownerDN)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to CEPHFS Owner group %s: %w", ownerUsername, cephfsName, err)
	}

	// Add the user to the admins group
	cephfsAdminsGroupDN, err := getCEPHFSAdminsGroupDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS admins group DN: %w", err)
	}
	err = ld.AddUserToGroup(ctx, cephfsAdminsGroupDN, ownerDN)
	if err != nil {
		return fmt.Errorf("failed to add Owner user %s to CEPHFS admins group %s: %w", ownerUsername, cephfsName, err)
	}

	return nil
}

func CephfsList(ctx context.Context) ([]string, error) {
	// List all cephfs
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	allCephfsDN := cfg.LDAPCephfsDN

	slog.Debug("AllCephfsDN ", "allCephfsDN", allCephfsDN)
	cephfs, err := ld.GetGroupNamesInOU(ctx, allCephfsDN, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephfs: %w", err)
	}
	cephfsGroupNameRegex, err := cephfsGroupNameRegex(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS group name regex: %w", err)
	}
	var cephfsGroupNames []string
	for _, ceph := range cephfs {
		if matched, err := regexp.MatchString(cephfsGroupNameRegex, ceph); err != nil {
			return nil, fmt.Errorf("failed to match CEPHFS group name regex: %w", err)
		} else if matched {
			cephfsGroupNames = append(cephfsGroupNames, ceph)
		}
	}
	var cephfsShortNames []string
	for _, ceph := range cephfsGroupNames {
		shortName, err := ConvertCEPHGroupNametoShortName(ceph)
		if err != nil {
			return nil, fmt.Errorf("failed to convert CEPHFS group name to short name: %w", err)
		}
		cephfsShortNames = append(cephfsShortNames, shortName)
	}
	slices.Sort(cephfsShortNames)
	slog.Debug("CEPHFS names", "cephfsShortNames", cephfsShortNames)
	return cephfsShortNames, nil
}

// CephfsAddMember adds a member to the CEPHFS with the given name.
func CephfsAddMember(ctx context.Context, cephfsName string, member string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is already a member of the CEPHFS
	inGroup, err := ld.UserInGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User already in CEPHFS", "userDN", userDN, "cephfsDN", cephfsDN)
		return nil
	}

	// Add the user to the CEPHFS group
	slog.Debug("Adding user to CEPHFS", "userDN", userDN, "cephfsDN", cephfsDN)
	err = ld.AddUserToGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to CEPHFS %s: %w", member, cephfsName, err)
	}
	slog.Debug("Added user to CEPHFS", "userDN", userDN, "cephfsDN", cephfsDN)

	// Add the user to the top level users group
	err = addUserToTopLevelUsersGroup(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to add user %s to top level users group: %w", member, err)
	}

	return nil
}

// CephfsRemoveMember removes a member from the CEPHFS with the given name.
//
// It will remove them from the CEPHFS group, all subgroups, the admin group, and the Owner group.
// If the user is not a member of any other CEPHFSs, they will also be removed from the top level users and admins groups.
func CephfsRemoveMember(ctx context.Context, name string, member string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is a member of the CEPHFS
	inGroup, err := ld.UserInGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in CEPHFS", "userDN", userDN, "cephfsDN", cephfsDN)
		return nil
	}

	// Check if the user is the Owner of the CEPHFS
	cephfsOWNERGroupDN, err := getCEPHFSOWNERGroupDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS Owner group DN: %w", err)
	}
	inGroup, err = ld.UserInGroup(ctx, cephfsOWNERGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	// if user is Owner, error
	if inGroup {
		return fmt.Errorf("user %s is the Owner of cephfs %s, cannot remove without setting a new Owner", member, name)
	}

	// Remove the user from the CEPHFS group
	err = ld.RemoveUserFromGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from CEPHFS %s: %w", member, name, err)
	}
	slog.Debug("Removed user from CEPHFS", "userDN", userDN, "cephfsDN", cephfsDN)

	// Remove the user from all subgroups of the CEPHFS
	slog.Debug("Removing user from CEPHFS subgroups", "userDN", userDN)
	cephfsSubgroupOUDN, err := getCEPHFSSubgroupOUDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS subgroup OU DN: %w", err)
	}
	subgroups, err := ld.GetGroupDNsInOU(ctx, cephfsSubgroupOUDN)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS subgroups: %w", err)
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
			return fmt.Errorf("failed to remove user %s from CEPHFS  subgroup %s: %w", member, subgroupDN, err)
		}
		slog.Debug("Removed user from subgroup", "subgroupDN", subgroupDN, "userDN", userDN)
	}

	// Remove the user from the CEPHFS Admins group if they're an admin
	cephfsAdminsGroupDN, err := getCEPHFSAdminsGroupDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS  admins group DN: %w", err)
	}
	inGroup, err = ld.UserInGroup(ctx, cephfsAdminsGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User is an admin, removing from CEPHFS admins group", "userDN", userDN, "cephfsAdminsGroupDN", cephfsAdminsGroupDN)
		err = ld.RemoveUserFromGroup(ctx, cephfsAdminsGroupDN, userDN)
		if err != nil {
			return fmt.Errorf("failed to remove user %s from CEPHFS admins group %s: %w", member, name, err)
		}
		slog.Debug("Removed user from CEPHFS admins group", "userDN", userDN, "OwnerrgAdminsGroupDN", cephfsAdminsGroupDN)
	}

	// Remove the user from the CEPHFS Owner group if they're a Owner
	cephfsOWNERGroupDN, err = getCEPHFSOWNERGroupDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS OWNER group DN: %w", err)
	}
	inGroup, err = ld.UserInGroup(ctx, cephfsOWNERGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User is a OWNER, removing from CEPHFS OWNER group", "userDN", userDN, "cephfsOwnerGroupDN", cephfsOWNERGroupDN)
		err = ld.RemoveUserFromGroup(ctx, cephfsOWNERGroupDN, userDN)
		if err != nil {
			return fmt.Errorf("failed to remove user %s from CEPHFS Owner group %s: %w", member, name, err)
		}
		slog.Debug("Removed user from CEPHFS Owner group", "userDN", userDN, "cephfsOwnerGroupDN", cephfsOWNERGroupDN)
	}

	// // Remove the user from the top level admins group if they are not an admin in any other CEPHFS
	// adminInAnyCEPHFS, err := userIsAdminInAnyCEPHFS(ctx, member)
	// if err != nil {
	// 	return fmt.Errorf("failed to check if user is admin in any CEPHFS: %w", err)
	// }
	// if !adminInAnyCEPHFS {
	// 	err = removeUserFromTopLevelAdminsGroup(ctx, member)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to remove user %s from top level admins group: %w", member, err)
	// 	}
	// } else {
	// 	slog.Debug("User still an admin in another CEPHFS, not removing from top level admin group", "userDN", userDN)
	// }
	//
	// // Remove the user from the top level users group if they are not in any other CEPHFS
	// inAnyCEPHFS, err := userInAnyCEPHFS(ctx, member)
	// if err != nil {
	// 	return fmt.Errorf("failed to check if user is in any CEPHFS: %w", err)
	// }
	// if !inAnyCEPHFS {
	// 	err = removeUserFromTopLevelUsersGroup(ctx, member)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to remove user %s from top level users group: %w", member, err)
	// 	}
	// } else {
	// 	slog.Debug("User still in another CEPHFS, not removing from top level user group", "userDN", userDN)
	// }
	return nil
}

func CephfsListMemberUsernames(ctx context.Context, name string) ([]string, error) {
	// List all members of the CEPHFS with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSDN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	members, err := ld.GetGroupMemberUsernames(ctx, cephfsDN)

	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// CephfsListMemberDNs lists all member DNs of the CEPHFS with the given name.
func CephfsListMemberDNs(ctx context.Context, name string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSDN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	members, err := ld.GetGroupMemberDNs(ctx, cephfsDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// CephfsListAdminUsernames lists all admin usernames of the CEPHFS with the given name.
func CephfsListAdminUsernames(ctx context.Context, name string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSAdminsGroupDN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	admins, err := ld.GetGroupMemberUsernames(ctx, cephfsDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(admins)
	return admins, nil
}

// CephfsAddAdmin adds an admin to the CEPHFS with the given name.
func CephfsAddAdmin(ctx context.Context, cephfsName string, adminUsername string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	adminGroupDN, err := getCEPHFSAdminsGroupDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS admin group DN: %w", err)
	}
	userDN, err := getUserDN(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the CEPHFS group exists
	cephfsDN, found, err := findCEPHFSDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to find CEPHFS DN: %w", err)
	}
	if !found {
		slog.Debug("CEPHFS not found", "name", cephfsName)
		return fmt.Errorf("CEPHFS %s not found", cephfsName)
	}

	// Check if the user is a member of the CEPHFS group
	inCEPHFS, err := ld.UserInGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inCEPHFS {
		slog.Debug("User not in CEPHFS", "userDN", userDN, "cephfsDN", cephfsDN)
		return fmt.Errorf("user %s is not a member of CEPHFS %s", adminUsername, cephfsName)
	}

	// Check if the user is already an admin of the CEPHFS group
	inAdminsGroup, err := ld.UserInGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inAdminsGroup {
		slog.Debug("User already in CEPHFS admins group", "userDN", userDN, "cephfsDN", adminGroupDN)
		return nil
	}

	// Add the user to the CEPHFS admins group
	err = ld.AddUserToGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add admin %s to CEPHFS %s: %w", adminUsername, cephfsName, err)
	}
	slog.Debug("Added admin to CEPHFS", "userDN", userDN, "cephfsDN", adminGroupDN)

	// Add the user to the top level admins group
	err = addUsertoTopLevelAdminsGroup(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to add admin %s to top level admins group: %w", adminUsername, err)
	}

	return nil
}

// CephfsRemoveAdmin removes an admin from the CEPHFS with the given name.
func CephfsRemoveAdmin(ctx context.Context, cephfsName string, adminUsername string) error {
	// Remove an admin from the CEPHFS with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	adminGroupDN, err := getCEPHFSAdminsGroupDN(ctx, cephfsName)
	if err != nil { 
		return fmt.Errorf("failed to get CEPHFS admin group DN: %w", err)
	}
	userDN, err := getUserDN(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is an admin of the CEPHFS
	inGroup, err := ld.UserInGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in CEPHFS admins group", "userDN", userDN, "cephfsDN", adminGroupDN)
		return nil
	}

	// Remove the user from the CEPHFS admins group
	err = ld.RemoveUserFromGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove admin %s from CEPHFS %s: %w", adminUsername, cephfsName, err)
	}
	slog.Debug("Removed admin from CEPHFS", "userDN", userDN, "cephfsDN", adminGroupDN)

	// Remove the user from the top level admins if they are not an admin of any other CEPHFS
	isAdminInAnotherCEPHFS, err := userIsAdminInAnyCEPHFS(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to check if user is admin in any CEPHFS: %w", err)
	}
	if !isAdminInAnotherCEPHFS {
		err = removeUserFromTopLevelAdminsGroup(ctx, adminUsername)
		if err != nil {
			return fmt.Errorf("failed to remove admin %s from top level admins group: %w", adminUsername, err)
		}
	} else {
		slog.Debug("User still an admin in another CEPHFS, not removing from top level admins group", "userDN", userDN)
	}

	return nil
}

// CephfsSubgroupExists checks if the subgroup with the given name exists under the CEPHFS.
func CephfsSubgroupExists(ctx context.Context, cephfsName string, subgroupName string) (bool, error) {
	// Check if the subgroup with the given name exists under the CEPHFS
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return false, fmt.Errorf("failed to get CEPHFS subgroup DN: %w", err)
	}
	exists, err := ld.DNExists(ctx, subgroupDN)
	if err != nil {
		return false, fmt.Errorf("failed to check if group exists: %w", err)
	}
	return exists, nil
}

// CephfsSubgroupList lists all subgroups of the CEPHFS with the given name.
func CephfsSubgroupList(ctx context.Context, cephfsName string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	OwnerrgSubgroupsOUDN, err := getCEPHFSSubgroupOUDN(ctx, cephfsName)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS subgroup OU DN: %w", err)
	}
	subgroups, err := ld.GetGroupNamesInOU(ctx, OwnerrgSubgroupsOUDN, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS subgroups: %w", err)
	}
	shortNames := make([]string, len(subgroups))
	for i, subgroup := range subgroups {
		shortNames[i] = getCEPHFSSubgroupShortName(cephfsName, subgroup)
	}
	slices.Sort(shortNames)
	return shortNames, nil
}

// CephfsSubgroupCreate creates a new subgroup under the CEPHFS with the given name.
func CephfsSubgroupCreate(ctx context.Context, cephfsName string, subgroupName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS subgroup DN: %w", err)
	}
	subgroupOUDN, err := getCEPHFSSubgroupOUDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS subgroup OU DN: %w", err)
	}

	subgroupFullName, err := getCEPHFSSubgroupName(ctx, cephfsName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS subgroup full name: %w", err)
	}

	// Create the subgroup object inside the CEPHFS OU/Groups
	gidNumber, err := ld.GetNextGidNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next GID number: %w", err)
	}
	err = ld.CreateGroup(ctx, subgroupOUDN, subgroupFullName, gidNumber)
	if err != nil {
		return fmt.Errorf("failed to create CEPHFS subgroup object: %w", err)
	}
	slog.Debug("Created CEPHFS subgroup object", "subgroupDN", subgroupDN)

	return nil
}

// CephfsSubgroupDelete deletes the subgroup with the given name under the CEPHFS groups OU.
// If the subgroup is found, it returns true and nil.
func CephfsSubgroupDelete(ctx context.Context, cephfsName string, subgroupName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS subgroup DN: %w", err)
	}

	// Check if the subgroup exists
	exists, err := ld.DNExists(ctx, subgroupDN)
	if err != nil {
		return fmt.Errorf("failed to check if group exists: %w", err)
	}
	if !exists {
		slog.Debug("CEPHFS subgroup does not exist", "subgroupDN", subgroupDN)
		return nil
	}

	// Delete the subgroup object
	err = ld.DeleteGroup(ctx, subgroupDN)
	if err != nil {
		return fmt.Errorf("failed to delete CEPHFS subgroup object: %w", err)
	}
	slog.Debug("Deleted CEPHFS subgroup object", "subgroupDN", subgroupDN)

	return nil
}

// CephfsSubgroupListMemberUsernames lists all members of the subgroup with the given name under the CEPHFS.
func CephfsSubgroupListMemberUsernames(ctx context.Context, cephfsName string, subgroupName string) ([]string, error) {
	// List all members of the subgroup with the given name under the CEPHFS
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS subgroup DN: %w", err)
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

// CephfsSubgroupListMemberDNs lists all members of the subgroup with the given name under the CEPHFS.
func CephfsSubgroupListMemberDNs(ctx context.Context, cephfsName string, subgroupName string) ([]string, error) {
	// List all members of the subgroup with the given name under the CEPHFS
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS subgroup DN: %w", err)
	}
	members, err := ld.GetGroupMemberDNs(ctx, subgroupDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// CephfsSubgroupAddMember adds a member to the subgroup with the given name under the CEPHFS.
func CephfsSubgroupAddMember(ctx context.Context, cephfsName string, subgroupName string, memberUsername string) error {
	// Check if memberUsername is in the CEPHFS
	cephfsDN, err := getCEPHFSDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	userDN, err := getUserDN(ctx, memberUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}
	inGroup, err := ld.UserInGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		return fmt.Errorf("user %s is not a member of the CEPHFS %s", memberUsername, cephfsName)
	}

	// Add a member to the subgroup with the given name under the CEPHFS
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS subgroup DN: %w", err)
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
		slog.Debug("User already in CEPHFS subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
		return nil
	}

	// Add the user to the subgroup group
	err = ld.AddUserToGroup(ctx, subgroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to CEPHFS subgroup %s: %w", memberUsername, subgroupName, err)
	}
	slog.Debug("Added user to CEPHFS subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
	return nil
}

// CephfsSubgroupRemoveMember removes a member from the subgroup with the given name under the CEPHFS.
func CephfsSubgroupRemoveMember(ctx context.Context, cephfsName string, subgroupName string, memberUsername string) error {
	// Remove a member from the subgroup with the given name under the CEPHFS
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS subgroup DN: %w", err)
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
		slog.Debug("User not in CEPHFS subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
		return nil
	}

	// Remove the user from the subgroup group
	err = ld.RemoveUserFromGroup(ctx, subgroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from CEPHFS subgroup %s: %w", memberUsername, subgroupName, err)
	}
	slog.Debug("Removed user from CEPHFS subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
	return nil
}

// CephfsSubgroupListNames lists all subgroup names of the CEPHFS with the given name.
func CephfsSubgroupListNames(ctx context.Context, cephfsName string) ([]string, error) {
	// List all subgroups of the CEPHFS with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephfsOUDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	subgroupsDN := fmt.Sprintf("OU=Groups,%s", cephfsOUDN)
	subgroups, err := ld.GetGroupNamesInOU(ctx, subgroupsDN, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS subgroups: %w", err)
	}
	slices.Sort(subgroups)
	return subgroups, nil
}

// CephfsSubgroupListDNs lists all subgroup DNs of the CEPHFS with the given name.
func CephfsSubgroupListDNs(ctx context.Context, cephfsName string) ([]string, error) {
	// List all subgroups of the CEPHFS with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephfsOUDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS DN: %w", err)
	}
	subgroupsDN := fmt.Sprintf("OU=Groups,%s", cephfsOUDN)
	subgroups, err := ld.GetGroupDNsInOU(ctx, subgroupsDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPHFS subgroups: %w", err)
	}
	slices.Sort(subgroups)
	return subgroups, nil
}
