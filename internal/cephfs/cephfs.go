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
	topLevelAdminsGroupDN = "CN=IS.RACS.Talapas.PirgAdmins,OU=RACS,OU=Groups,OU=IS,OU=Units,DC=ad,DC=uoregon,DC=edu"
)

func ConvertCEPHGroupNametoShortName(cephfsName string) (string, error) {
	slog.Debug("Converting PIRG group name to short name", "cephfsName", cephfsName)
	parts := strings.Split(cephfsName, ".")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid PIRG group name: %s", cephfsName)
	}
	shortName := parts[len(parts)-1]
	slog.Debug("Converted PIRG group name to short name", "shortName", shortName)
	return shortName, nil
}

// pirgGroupNameRegex returns the regex for the PIRG group name.
// This is used to match only the PIRG groups in the LDAP directory,
// not the subgroups or any others.
func cephfsGroupNameRegex(ctx context.Context) (string, error) {
	// Initialize the PIRG group name regex
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsGroupNameRegex := fmt.Sprintf("^%s([a-zA-Z0-9_\\-]+)$", groupPrefix)
	slog.Debug("PIRG group name regex", "regex", cephfsGroupNameRegex)
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

// getPIRGSubgroupOUDN returns the DistinguishedName of the PIRG subgroup OU with the given name.
func getCEPHFSSubgroupOUDN(ctx context.Context, cephfsName string) (string, error) {
	slog.Debug("Getting CEPHFS subgroup OU DN", "cephfsName", cephfsName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	n := fmt.Sprintf("OU=Groups,%s", cephfsDN)
	slog.Debug("CEPHFS subgroup OU DN", "dn", n)
	return n, nil
}

// getPIRGOUDN returns the DistinguishedName of the PIRG OU with the given name.
// for example: OU=pirg_name,OU=PIRGs,DC=example,DC=com
func getCEPHFSOUDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting PIRG OU DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	baseDN := cfg.LDAPCephfsDN
	n := fmt.Sprintf("OU=%s,%s", name, baseDN)
	slog.Debug("CEPHFS OU DN", "dn", n)
	return n, nil
}

// getCEPHFSDN returns the DistinguishedName of the PIRG with the given name.
// if not found, it returns an error.
func getCEPHFSDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting PIRG DN", "name", name)
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
		return "", fmt.Errorf("failed to get PIRG full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", groupName, cephfsDN)
	slog.Debug("CEPHFS DN", "dn", n)
	return n, nil
}

// findCEPHFSDN returns the DistinguishedName of the PIRG with the given name.
// includes a check if the group exists.
// if not found, it returns an empty string, false, and nil
func findCEPHFSDN(ctx context.Context, name string) (string, bool, error) {
	slog.Debug("Finding CEPHFS DN", "name", name)
	groupName, err := getCEPHFSFullName(ctx, name)
	if err != nil {
		return "", false, fmt.Errorf("failed to get PIRG full name: %w", err)
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

// getPIRGSubgroupShortName returns the short name of the PIRG subgroup with the given name.
// for example: myprefix.groupname.subgroup_name -> subgroup_name
func getCEPHFSSubgroupShortName(cephfsName string, subgroupName string) string {
	slog.Debug("Getting CEPHFS subgroup short name", "cephfsName", cephfsName, "subgroupName", subgroupName)
	parts := strings.Split(subgroupName, ".")
	n := parts[len(parts)-1]
	slog.Debug("CEPHFS subgroup short name", "name", n)
	return n
}

// getPIRGAdminsGroupDN returns the DistinguishedName of the PIRG Admins group with the given name.
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

// getPIRGPIGroupDN returns the DistinguishedName of the PIRG PI group with the given name.
func getCEPHFSOWNERGroupDN(ctx context.Context, cephfsName string) (string, error) {
	slog.Debug("Getting PIRG PI group DN", "cephfsName", cephfsName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	piGroupFullName, err := getCEPHFSOWNERGroupFullName(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG PI group full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", piGroupFullName, cephfsDN)
	slog.Debug("PIRG PI group DN", "dn", n)
	return n, nil
}

// getCEPHFSSubgroupDN returns the DistinguishedName of the PIRG subgroup with the given name.
func getCEPHFSSubgroupDN(ctx context.Context, cephfsName string, subgroupName string) (string, error) {
	slog.Debug("Getting PIRG subgroup DN", "cephfsName", cephfsName, "subgroupName", subgroupName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	subgroupFullName, err := getCEPHFSSubgroupName(ctx, cephfsName, subgroupName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG subgroup full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,OU=Groups,%s", subgroupFullName, cephfsDN)
	slog.Debug("PIRG subgroup DN", "dn", n)
	return n, nil
}

// getPIRGSubgroupName returns the name of the PIRG subgroup with the given name.
func getCEPHFSSubgroupName(ctx context.Context, cephfsName string, subgroupName string) (string, error) {
	slog.Debug("Getting CEPHFS subgroup name", "cephfsName", cephfsName, "subgroupName", subgroupName)
	cephfsFullName, err := getCEPHFSFullName(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG full name: %w", err)
	}
	subgroupFullName := fmt.Sprintf("%s.%s", cephfsFullName, subgroupName)
	slog.Debug("CEPHFS subgroup name", "name", subgroupFullName)
	return subgroupFullName, nil
}

// getAllPIRGDNs returns all the PIRG DNs in the LDAP directory.
func getAllCEPHFSDNs(ctx context.Context) ([]string, error) {
	slog.Debug("Getting all PIRG DNs")
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

// // userInAnyPIRG checks if the user is in any PIRG.
// func userInAnyPIRG(ctx context.Context, username string) (bool, error) {
// 	slog.Debug("Checking if user is in any PIRG", "username", username)
// 	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
// 	if cfg == nil {
// 		return false, fmt.Errorf("config not found in context")
// 	}
// 	userDN, err := getUserDN(ctx, username)
// 	if err != nil {
// 		return false, fmt.Errorf("failed to get user DN: %w", err)
// 	}
// 	userGroups, err := ld.GetGroupsForUser(ctx, userDN)
// 	if err != nil {
// 		return false, fmt.Errorf("failed to get user groups: %w", err)
// 	}
// 	for _, groupDN := range userGroups {
// 		groupName, err := ld.ConvertDNToObjectName(groupDN)
// 		if err != nil {
// 			return false, fmt.Errorf("failed to convert DN to object name: %w", err)
// 		}
// 		if strings.HasPrefix(groupName, groupPrefix) {
// 			slog.Debug("User found in some PIRG", "userDN", userDN, "groupDN", groupDN)
// 			return true, nil
// 		}
// 	}
// 	slog.Debug("User not found in any PIRG")
// 	return false, nil
// }

// userIsAdminInAnyPIRG checks if the user is an admin in any PIRG.
// func userIsAdminInAnyPIRG(ctx context.Context, username string) (bool, error) {
// 	slog.Debug("Checking if user is admin in any PIRG", "username", username)
// 	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
// 	if cfg == nil {
// 		return false, fmt.Errorf("config not found in context")
// 	}
// 	userDN, err := getUserDN(ctx, username)
// 	if err != nil {
// 		return false, fmt.Errorf("failed to get user DN: %w", err)
// 	}
// 	userGroups, err := ld.GetGroupsForUser(ctx, userDN)
// 	if err != nil {
// 		return false, fmt.Errorf("failed to get user groups: %w", err)
// 	}
// 	for _, groupDN := range userGroups {
// 		groupName, err := ld.ConvertDNToObjectName(groupDN)
// 		if err != nil {
// 			return false, fmt.Errorf("failed to convert DN to object name: %w", err)
// 		}
// 		// This is gross, but whatever
// 		// Each groupName returned could be anything from "is.racs.pirg.somepirg"
// 		//   to "is.racs.pirg.somepirg.admins", so we strip off the prefix
// 		//	 which leaves "somepirg" or "somepirg.admins",
// 		//   and since we want to get the admins group, we check if the name
// 		//   contains a period, which means it's something OTHER than the pirg name
// 		//	 and we ignore it. we only want to get the pirg name from the normal pirg group,
// 		//	 not the admins, pi, or other groups.
// 		if strings.HasPrefix(groupName, groupPrefix) {
// 			cephfsName := strings.TrimPrefix(groupName, groupPrefix)
// 			if strings.Contains(cephfsName, ".") {
// 				// this is admins,pi, or subgroup, ignore it
// 				continue
// 			}
// 			pirgAdminsGroupDN, err := getPIRGAdminsGroupDN(ctx, cephfsName)
// 			if err != nil {
// 				return false, fmt.Errorf("failed to get PIRG admins group DN: %w", err)
// 			}
// 			inGroup, err := ld.UserInGroup(ctx, pirgAdminsGroupDN, userDN)
// 			if err != nil {
// 				return false, fmt.Errorf("failed to check if user is in group: %w", err)
// 			}
// 			if inGroup {
// 				slog.Debug("User found as admin in PIRG", "userDN", userDN, "groupDN", groupDN)
// 				return true, nil
// 			}
// 			continue
// 		}
// 	}
// 	slog.Debug("User not found as admin in any PIRG")
// 	return false, nil
// }

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

	// Check if the CEPHFS already exists
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

	// Create the CEPHFS OU inside the CEPHFSS base DN
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

	// Create the CEPHFS PI group object
	cephfsOwnerGroupFullName, err := getCEPHFSOWNERGroupFullName(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS OWNER group full name: %w", err)
	}
	slog.Debug("CEPHFS OWNER group name", "pirgPIGroupName", cephfsOwnerGroupFullName)
	err = ld.CreateGroup(ctx, cephfsOUDN, cephfsOwnerGroupFullName, gidNumber+2)
	if err != nil {
		return fmt.Errorf("failed to create CEPHFS OWNER group object: %w", err)
	}
	slog.Debug("Created CEPHFS OWNER group object", "cephfsOwnerGroupName", cephfsOwnerGroupFullName)

	// Add the PI to the CEPHFS PI group
	err = PirgSetPI(ctx, cephfsName, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to add PI user %s to CEPHFS PI group %s: %w", ownerUsername, cephfsName, err)
	}
	slog.Debug("Added PI to CEPHFS PI group", "ownerUsername", piUsername, "cephfsName", cephfsName)

	// Add the PI to the CEPHFS admins group
	err = PirgAddAdmin(ctx, cephfsName, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to add PI user %s to CEPHFS admins group %s: %w", ownerUsername, cephfsName, err)
	}
	slog.Debug("Added PI to CEPHFS admins group", "ownerUsername", piUsername, "cephfsName", cephfsName)

	// Add the PI to the CEPHFS group
	err = PirgAddMember(ctx, cephfsName, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to add PI user %s to CEPHFS %s: %w", ownerUsername, cephfsName, err)
	}
	slog.Debug("Added PI to CEPHFS group", "ownerUsername", piUsername, "cephfsName", cephfsName)

	return nil
}

// PirgDelete deletes the PIRG with the given name.
// It will error if there are any members in the group.
func CephfsDelete(ctx context.Context, cephfsName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephOUDN, err := getCEPHFSOUDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	// Check if the PIRG exists
	cephDN, found, err := findCEPHFSDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to find PIRG DN: %w", err)
	}
	if !found {
		slog.Debug("PIRG not found", "name", cephfsName)
		return nil
	}
	members, err := ld.GetGroupMemberUsernames(ctx, cephDN)
	if err != nil {
		return fmt.Errorf("failed to get group members: %w", err)
	}
	if len(members) > 1 {
		return fmt.Errorf("PIRG %s has non-PI members, cannot delete", cephfsName)
	}
	err = ld.DeleteOURecursively(ctx, cephOUDN)
	if err != nil {
		return fmt.Errorf("failed to delete PIRG group object: %w", err)
	}
	return nil
}

// PirgGetPI returns the PI username for the PIRG with the given name.
func CephfsGetOwnerUsername(ctx context.Context, cephfsName string) (string, error) {
	// Get the PI username for the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephfsOwnerGroupDN, err := getCEPHFSOWNERGroupDN(ctx, cephfsName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG PI group DN: %w", err)
	}
	members, err := ld.GetGroupMemberUsernames(ctx, cephfsOwnerGroupDN)
	if err != nil {
		return "", fmt.Errorf("failed to get group members: %w", err)
	}
	if len(members) == 0 {
		return "", fmt.Errorf("no PI found for PIRG %s", cephfsName)
	}
	if len(members) > 1 {
		return "", fmt.Errorf("multiple PIs found for PIRG %s", cephfsName)
	}
	return members[0], nil
}

func CEPHFSSetOWNER(ctx context.Context, cephfsName string, ownerUsername string) error {
	slog.Debug("Setting PI for PIRG", "cephfsName", cephfsName, "ownerUsername", ownerUsername)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephDN, err := getCEPHFSDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	ownerDN, err := getUserDN(ctx, ownerUsername)
	if err != nil {
		return fmt.Errorf("failed to get pi DN: %w", err)
	}
	// Remove existing PI from the PIRG PI group
	cephfsOwnerGroupDN, err := getCEPHFSOWNERGroupDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG PI group DN: %w", err)
	}
	// find existing users in the group
	existingMemberDNs, err := ld.GetGroupMemberDNs(ctx, cephfsOwnerGroupDN)
	if err != nil {
		return fmt.Errorf("failed to get group members: %w", err)
	}
	if len(existingMemberDNs) == 0 {
		slog.Debug("No existing PI found in PIRG PI group", "cephfsOwnerGroupDN", cephfsOwnerGroupDN)
	} else if len(existingMemberDNs) > 1 {
		slog.Debug("Multiple existing PIs found in PIRG PI group", "cephfsOwnerGroupDN", cephfsOwnerGroupDN)
	}
	for _, existingMemberDN := range existingMemberDNs {
		slog.Debug("Removing existing PI from PIRG PI group", "existingMemberDN", existingMemberDN)
		err = ld.RemoveUserFromGroup(ctx, cephfsOwnerGroupDN, existingMemberDN)
		if err != nil {
			return fmt.Errorf("failed to remove existing PI from PIRG PI group: %w", err)
		}
	}
	// Add the user to the PIRG
	err = ld.AddUserToGroup(ctx, cephDN, ownerDN)
	if err != nil {
		return fmt.Errorf("failed to add pi user %s to PIRG %s: %w", ownerUsername, cephfsName, err)
	}
	// Add the user to the PIRG PI group
	err = ld.AddUserToGroup(ctx, cephfsOwnerGroupDN, ownerDN)
	if err != nil {
		return fmt.Errorf("failed to add pi user %s to PIRG PI group %s: %w", ownerUsername, cephfsName, err)
	}

	// Add the user to the admins group
	cephfsAdminsGroupDN, err := getCEPHFSAdminsGroupDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG admins group DN: %w", err)
	}
	err = ld.AddUserToGroup(ctx, cephfsAdminsGroupDN, ownerDN)
	if err != nil {
		return fmt.Errorf("failed to add pi user %s to PIRG admins group %s: %w", ownerUsername, cephfsName, err)
	}

	return nil
}

func CephfsList(ctx context.Context) ([]string, error) {
	// List all cephfs
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	allCephfsDN := cfg.LDAPPirgDN
	cephfs, err := ld.GetGroupNamesInOU(ctx, allCephfsDN, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get cephfs: %w", err)
	}
	cephfsGroupNameRegex, err := cephfsGroupNameRegex(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG group name regex: %w", err)
	}
	var cephfsGroupNames []string
	for _, ceph := range cephfs {
		if matched, err := regexp.MatchString(cephfsGroupNameRegex, ceph); err != nil {
			return nil, fmt.Errorf("failed to match PIRG group name regex: %w", err)
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

// PirgAddMember adds a member to the PIRG with the given name.
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

	// Check if the user is already a member of the PIRG
	inGroup, err := ld.UserInGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User already in CEPHFS", "userDN", userDN, "cephfsDN", cephfsDN)
		return nil
	}

	// Add the user to the PIRG group
	slog.Debug("Adding user to PIRG", "userDN", userDN, "cephfsDN", cephfsDN)
	err = ld.AddUserToGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to PIRG %s: %w", member, cephfsName, err)
	}
	slog.Debug("Added user to PIRG", "userDN", userDN, "cephfsDN", cephfsDN)

	// Add the user to the top level users group
	err = addUserToTopLevelUsersGroup(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to add user %s to top level users group: %w", member, err)
	}

	return nil
}

// PirgRemoveMember removes a member from the PIRG with the given name.
//
// It will remove them from the PIRG group, all subgroups, the admin group, and the PI group.
// If the user is not a member of any other PIRGs, they will also be removed from the top level users and admins groups.
func CephfsRemoveMember(ctx context.Context, name string, member string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is a member of the PIRG
	inGroup, err := ld.UserInGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in PIRG", "userDN", userDN, "cephfsDN", cephfsDN)
		return nil
	}

	// Check if the user is the PI of the PIRG
	cephfsOWNERGroupDN, err := getCEPHFSOWNERGroupDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get PIRG PI group DN: %w", err)
	}
	inGroup, err = ld.UserInGroup(ctx, cephfsOWNERGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	// if user is PI, error
	if inGroup {
		return fmt.Errorf("user %s is the Owner of cephfs %s, cannot remove without setting a new PI", member, name)
	}

	// Remove the user from the PIRG group
	err = ld.RemoveUserFromGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from CEPHFS %s: %w", member, name, err)
	}
	slog.Debug("Removed user from CEPHFS", "userDN", userDN, "cephfsDN", cephfsDN)

	// Remove the user from all subgroups of the PIRG
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

	// Remove the user from the PIRG Admins group if they're an admin
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
		slog.Debug("Removed user from CEPHFS admins group", "userDN", userDN, "pirgAdminsGroupDN", cephfsAdminsGroupDN)
	}

	// Remove the user from the PIRG PI group if they're a PI
	cephfsOwnerGroupDN, err = getCEPHFSOWNERGroupDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get CEPHFS OWNER group DN: %w", err)
	}
	inGroup, err = ld.UserInGroup(ctx, cephfsOwnerGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User is a OWNER, removing from CEPHFS OWNER group", "userDN", userDN, "cephfsOwnerGroupDN", cephfsOwnerGroupDN)
		err = ld.RemoveUserFromGroup(ctx, pirgPIGroupDN, userDN)
		if err != nil {
			return fmt.Errorf("failed to remove user %s from CEPHFS Owner group %s: %w", member, name, err)
		}
		slog.Debug("Removed user from PIRG PI group", "userDN", userDN, "cephfsOwnerGroupDN", cephfsOwnerGroupDN)
	}

	// // Remove the user from the top level admins group if they are not an admin in any other PIRG
	// adminInAnyPIRG, err := userIsAdminInAnyPIRG(ctx, member)
	// if err != nil {
	// 	return fmt.Errorf("failed to check if user is admin in any PIRG: %w", err)
	// }
	// if !adminInAnyPIRG {
	// 	err = removeUserFromTopLevelAdminsGroup(ctx, member)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to remove user %s from top level admins group: %w", member, err)
	// 	}
	// } else {
	// 	slog.Debug("User still an admin in another PIRG, not removing from top level admin group", "userDN", userDN)
	// }
	//
	// // Remove the user from the top level users group if they are not in any other PIRG
	// inAnyPIRG, err := userInAnyPIRG(ctx, member)
	// if err != nil {
	// 	return fmt.Errorf("failed to check if user is in any PIRG: %w", err)
	// }
	// if !inAnyPIRG {
	// 	err = removeUserFromTopLevelUsersGroup(ctx, member)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to remove user %s from top level users group: %w", member, err)
	// 	}
	// } else {
	// 	slog.Debug("User still in another PIRG, not removing from top level user group", "userDN", userDN)
	// }
	return nil
}

func CephfsListMemberUsernames(ctx context.Context, name string) ([]string, error) {
	// List all members of the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSDN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	members, err := ld.GetGroupMemberUsernames(ctx, cephfsDN)

	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// PirgListMemberDNs lists all member DNs of the PIRG with the given name.
func CephfsListMemberDNs(ctx context.Context, name string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getCEPHFSDN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	members, err := ld.GetGroupMemberDNs(ctx, cephfsDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// PirgListAdminUsernames lists all admin usernames of the PIRG with the given name.
func CephfsListAdminUsernames(ctx context.Context, name string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephfsDN, err := getPIRGAdminsGroupDN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	admins, err := ld.GetGroupMemberUsernames(ctx, cephfsDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(admins)
	return admins, nil
}

// PirgAddAdmin adds an admin to the PIRG with the given name.
func CephfsAddAdmin(ctx context.Context, cephfsName string, adminUsername string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	adminGroupDN, err := getPIRGAdminsGroupDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG admin group DN: %w", err)
	}
	userDN, err := getUserDN(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the PIRG exists
	cephfsDN, found, err := findCEPHFSDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to find PIRG DN: %w", err)
	}
	if !found {
		slog.Debug("PIRG not found", "name", cephfsName)
		return fmt.Errorf("PIRG %s not found", cephfsName)
	}

	// Check if the user is a member of the PIRG
	inPIRG, err := ld.UserInGroup(ctx, cephfsDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inPIRG {
		slog.Debug("User not in CEPHFS", "userDN", userDN, "cephfsDN", cephfsDN)
		return fmt.Errorf("user %s is not a member of PIRG %s", adminUsername, cephfsName)
	}

	// Check if the user is already an admin of the PIRG
	inAdminsGroup, err := ld.UserInGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inAdminsGroup {
		slog.Debug("User already in PIRG admins group", "userDN", userDN, "cephfsDN", adminGroupDN)
		return nil
	}

	// Add the user to the PIRG admins group
	err = ld.AddUserToGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add admin %s to PIRG %s: %w", adminUsername, cephfsName, err)
	}
	slog.Debug("Added admin to PIRG", "userDN", userDN, "cephfsDN", adminGroupDN)

	// Add the user to the top level admins group
	err = addUsertoTopLevelAdminsGroup(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to add admin %s to top level admins group: %w", adminUsername, err)
	}

	return nil
}

// PirgRemoveAdmin removes an admin from the PIRG with the given name.
func PirgRemoveAdmin(ctx context.Context, cephfsName string, adminUsername string) error {
	// Remove an admin from the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	adminGroupDN, err := getPIRGAdminsGroupDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG admin group DN: %w", err)
	}
	userDN, err := getUserDN(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is an admin of the PIRG
	inGroup, err := ld.UserInGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in PIRG admins group", "userDN", userDN, "cephfsDN", adminGroupDN)
		return nil
	}

	// Remove the user from the PIRG admins group
	err = ld.RemoveUserFromGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove admin %s from PIRG %s: %w", adminUsername, cephfsName, err)
	}
	slog.Debug("Removed admin from PIRG", "userDN", userDN, "cephfsDN", adminGroupDN)

	// Remove the user from the top level admins if they are not an admin of any other PIRG
	isAdminInAnotherPIRG, err := userIsAdminInAnyPIRG(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to check if user is admin in any PIRG: %w", err)
	}
	if !isAdminInAnotherPIRG {
		err = removeUserFromTopLevelAdminsGroup(ctx, adminUsername)
		if err != nil {
			return fmt.Errorf("failed to remove admin %s from top level admins group: %w", adminUsername, err)
		}
	} else {
		slog.Debug("User still an admin in another PIRG, not removing from top level admins group", "userDN", userDN)
	}

	return nil
}

// PirgSubgroupExists checks if the subgroup with the given name exists under the PIRG.
func PirgSubgroupExists(ctx context.Context, cephfsName string, subgroupName string) (bool, error) {
	// Check if the subgroup with the given name exists under the PIRG
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return false, fmt.Errorf("failed to get PIRG subgroup DN: %w", err)
	}
	exists, err := ld.DNExists(ctx, subgroupDN)
	if err != nil {
		return false, fmt.Errorf("failed to check if group exists: %w", err)
	}
	return exists, nil
}

// PirgSubgroupList lists all subgroups of the PIRG with the given name.
func PirgSubgroupList(ctx context.Context, cephfsName string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	pirgSubgroupsOUDN, err := getPIRGSubgroupOUDN(ctx, cephfsName)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroup OU DN: %w", err)
	}
	subgroups, err := ld.GetGroupNamesInOU(ctx, pirgSubgroupsOUDN, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroups: %w", err)
	}
	shortNames := make([]string, len(subgroups))
	for i, subgroup := range subgroups {
		shortNames[i] = getPIRGSubgroupShortName(cephfsName, subgroup)
	}
	slices.Sort(shortNames)
	return shortNames, nil
}

// PirgSubgroupCreate creates a new subgroup under the PIRG with the given name.
func PirgSubgroupCreate(ctx context.Context, cephfsName string, subgroupName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroup DN: %w", err)
	}
	subgroupOUDN, err := getPIRGSubgroupOUDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroup OU DN: %w", err)
	}

	subgroupFullName, err := getPIRGSubgroupName(ctx, cephfsName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroup full name: %w", err)
	}

	// Create the subgroup object inside the PIRG OU/Groups
	gidNumber, err := ld.GetNextGidNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next GID number: %w", err)
	}
	err = ld.CreateGroup(ctx, subgroupOUDN, subgroupFullName, gidNumber)
	if err != nil {
		return fmt.Errorf("failed to create PIRG subgroup object: %w", err)
	}
	slog.Debug("Created PIRG subgroup object", "subgroupDN", subgroupDN)

	return nil
}

// PirgSubgroupDelete deletes the subgroup with the given name under the PIRG groups OU.
// If the subgroup is found, it returns true and nil.
func CephfsSubgroupDelete(ctx context.Context, cephfsName string, subgroupName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroup DN: %w", err)
	}

	// Check if the subgroup exists
	exists, err := ld.DNExists(ctx, subgroupDN)
	if err != nil {
		return fmt.Errorf("failed to check if group exists: %w", err)
	}
	if !exists {
		slog.Debug("PIRG subgroup does not exist", "subgroupDN", subgroupDN)
		return nil
	}

	// Delete the subgroup object
	err = ld.DeleteGroup(ctx, subgroupDN)
	if err != nil {
		return fmt.Errorf("failed to delete PIRG subgroup object: %w", err)
	}
	slog.Debug("Deleted PIRG subgroup object", "subgroupDN", subgroupDN)

	return nil
}

// PirgSubgroupListMemberUsernames lists all members of the subgroup with the given name under the PIRG.
func CephfsSubgroupListMemberUsernames(ctx context.Context, cephfsName string, subgroupName string) ([]string, error) {
	// List all members of the subgroup with the given name under the PIRG
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroup DN: %w", err)
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

// PirgSubgroupListMemberDNs lists all members of the subgroup with the given name under the PIRG.
func CephfsSubgroupListMemberDNs(ctx context.Context, cephfsName string, subgroupName string) ([]string, error) {
	// List all members of the subgroup with the given name under the PIRG
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroup DN: %w", err)
	}
	members, err := ld.GetGroupMemberDNs(ctx, subgroupDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// PirgSubgroupAddMember adds a member to the subgroup with the given name under the PIRG.
func CephfsSubgroupAddMember(ctx context.Context, cephfsName string, subgroupName string, memberUsername string) error {
	// Check if memberUsername is in the PIRG
	cephfsDN, err := getCEPHFSDN(ctx, cephfsName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
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
		return fmt.Errorf("user %s is not a member of the PIRG %s", memberUsername, cephfsName)
	}

	// Add a member to the subgroup with the given name under the PIRG
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getCEPHFSSubgroupDN(ctx, cephfsName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroup DN: %w", err)
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
		slog.Debug("User already in PIRG subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
		return nil
	}

	// Add the user to the subgroup group
	err = ld.AddUserToGroup(ctx, subgroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to PIRG subgroup %s: %w", memberUsername, subgroupName, err)
	}
	slog.Debug("Added user to PIRG subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
	return nil
}

// PirgSubgroupRemoveMember removes a member from the subgroup with the given name under the PIRG.
func PirgSubgroupRemoveMember(ctx context.Context, cephfsName string, subgroupName string, memberUsername string) error {
	// Remove a member from the subgroup with the given name under the PIRG
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
		slog.Debug("User not in PIRG subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
		return nil
	}

	// Remove the user from the subgroup group
	err = ld.RemoveUserFromGroup(ctx, subgroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from PIRG subgroup %s: %w", memberUsername, subgroupName, err)
	}
	slog.Debug("Removed user from PIRG subgroup", "userDN", userDN, "subgroupDN", subgroupDN)
	return nil
}

// PirgSubgroupListNames lists all subgroup names of the PIRG with the given name.
func PirgSubgroupListNames(ctx context.Context, cephfsName string) ([]string, error) {
	// List all subgroups of the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephfsOUDN, err := getPIRGOUDN(ctx, cephfsName)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	subgroupsDN := fmt.Sprintf("OU=Groups,%s", cephfsOUDN)
	subgroups, err := ld.GetGroupNamesInOU(ctx, subgroupsDN, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroups: %w", err)
	}
	slices.Sort(subgroups)
	return subgroups, nil
}

// PirgSubgroupListDNs lists all subgroup DNs of the PIRG with the given name.
func PirgSubgroupListDNs(ctx context.Context, cephfsName string) ([]string, error) {
	// List all subgroups of the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	cephfsOUDN, err := getPIRGOUDN(ctx, cephfsName)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	subgroupsDN := fmt.Sprintf("OU=Groups,%s", cephfsOUDN)
	subgroups, err := ld.GetGroupDNsInOU(ctx, subgroupsDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroups: %w", err)
	}
	slices.Sort(subgroups)
	return subgroups, nil
}
