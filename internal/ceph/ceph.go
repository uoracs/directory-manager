package ceph

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
	err                  error
	found                bool
	groupPrefix          = "is.racs.ceph."
	topLevelUsersGroupDN = "CN=IS.RACS.Talapas.Users,OU=RACS,OU=Groups,OU=IS,OU=Units,DC=ad,DC=uoregon,DC=edu"
)

func ConvertCephGroupNametoShortName(cephName string) (string, error) {
	slog.Debug("Converting CEPH group name to short name", "cephName", cephName)
	parts := strings.Split(cephName, ".")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid CEPH group name: %s", cephName)
	}
	shortName := parts[len(parts)-1]
	slog.Debug("Converted CEPH group name to short name", "shortName", shortName)
	return shortName, nil
}

func cephGroupNameRegex(ctx context.Context) (string, error) {
	// Initialize the CEPH group name regex
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephGroupNameRegex := fmt.Sprintf("^%s([a-zA-Z0-9_\\-]+)$", groupPrefix)
	slog.Debug("CEPH group name regex", "regex", cephGroupNameRegex)
	return cephGroupNameRegex, nil
}

func findCEPHDN(ctx context.Context, name string) (string, bool, error) {
	slog.Debug("Finding CEPH DN", "name", name)
	groupName, err := getCEPHFullName(ctx, name)
	if err != nil {
		return "", false, fmt.Errorf("failed to get CEPH full name: %w", err)
	}
	dn, found, err := ld.GetGroupDN(ctx, groupName)
	if !found && err == nil {
		slog.Debug("CEPH group not found", "name", name)
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("failed to get group DN: %w", err)
	}
	slog.Debug("CEPH DN found", "dn", dn)
	return dn, true, nil
}

func CephExists(ctx context.Context, name string) (bool, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	cephDN, found, err := findCEPHDN(ctx, name)
	if err != nil {
		return false, fmt.Errorf("failed to get CEPH DN: %w", err)
	}
	if !found {
		slog.Debug("CEPH not found", "name", name)
		return false, nil
	}
	slog.Debug("CEPH found", "name", name, "cephDN", cephDN)
	return true, nil
}

func CephList(ctx context.Context) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	allCephsDN := cfg.LDAPCephDN
	ceph_groups, err := ld.GetGroupNamesInOU(ctx, allCephsDN, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get Ceph groups: %w", err)
	}
	cephGroupNameRegex, err := cephGroupNameRegex(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPH group name regex: %w", err)
	}
	var cephGroupNames []string
	for _, ceph := range ceph_groups {
		if matched, err := regexp.MatchString(cephGroupNameRegex, ceph); err != nil {
			return nil, fmt.Errorf("failed to match CEPH group name regex: %w", err)
		} else if matched {
			cephGroupNames = append(cephGroupNames, ceph)
		}
	}
	var cephShortNames []string
	for _, ceph := range cephGroupNames {
		shortName, err := ConvertCephGroupNametoShortName(ceph)
		if err != nil {
			return nil, fmt.Errorf("failed to convert CEPH group name to short name: %w", err)
		}
		cephShortNames = append(cephShortNames, shortName)
	}
	slices.Sort(cephShortNames)
	slog.Debug("CEPH names", "cephShortNames", cephShortNames)
	return cephShortNames, nil
}

func getCEPHDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting CEPH DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	cephDN, err := getCEPHOUDN(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPH DN: %w", err)
	}
	groupName, err := getCEPHFullName(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get CEPH full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", groupName, cephDN)

	slog.Debug("CEPH DN", "dn", n)
	return n, nil
}

func getCEPHFullName(ctx context.Context, cephName string) (string, error) {
	slog.Debug("Getting CEPH group full name", "cephName", cephName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s", groupPrefix, cephName)
	slog.Debug("CEPH full name", "name", n)
	return n, nil
}

func getCEPHOUDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting CEPH OU DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	baseDN := cfg.LDAPCephDN
	// n := fmt.Sprintf("%s", name, baseDN)
	slog.Debug("CEPH OU DN", "dn", baseDN)

	return baseDN, nil
}

func CephListMemberUsernames(ctx context.Context, name string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}

	fullName, err := getCEPHFullName(ctx, name)

	baseDN := cfg.LDAPCephDN
	if err != nil {
		return nil, fmt.Errorf("failed to get CEPH DN: %w", err)
	}
	groupCN := fmt.Sprintf("cn=%s,%s", fullName, baseDN)
	members, err := ld.GetGroupMemberUsernames(ctx, groupCN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}

// CephAddMember adds a member to the CEPH group with the given name.
func CephAddMember(ctx context.Context, cephName string, member string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephDN, err := getCEPHDN(ctx, cephName)
	if err != nil {
		return fmt.Errorf("failed to get CEPH DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is already a member of the CEPH group
	inGroup, err := ld.UserInGroup(ctx, cephDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User already in CEPH group", "userDN", userDN, "cephDN", cephDN)
		return nil
	}

	// Add the user to the CEPH group
	slog.Debug("Adding user to CEPH", "userDN", userDN, "cephDN", cephDN)
	err = ld.AddUserToGroup(ctx, cephDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to CEPH %s: %w", member, cephName, err)
	}
	slog.Debug("Added user to CEPH", "userDN", userDN, "CEPHDN", cephDN)

	// Add the user to the top level users group
	err = addUserToTopLevelUsersGroup(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to add user %s to top level users group: %w", member, err)
	}

	return nil
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
func CephRemoveMember(ctx context.Context, name string, member string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephDN, err := getCEPHDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get CEPH DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is a member of the CEPH
	inGroup, err := ld.UserInGroup(ctx, cephDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in CEPH group", "userDN", userDN, "cephDN", cephDN)
		return nil
	}
	// Remove the user from the CEPH group
	err = ld.RemoveUserFromGroup(ctx, cephDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from CEPH %s: %w", member, name, err)
	}
	slog.Debug("Removed user from CEPH", "userDN", userDN, "cephDN", cephDN)

	return nil
}

func CephCreate(ctx context.Context, cephName string) error {
	slog.Debug("Creating CEPH group", "name", cephName)

	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}

	cephOUDN, err := getCEPHOUDN(ctx, cephName)
	if err != nil {
		return fmt.Errorf("failed to get CEPH OUDN : %w", err)
	}
	// Check if the Ceph already exists
	cephDN, found, err := findCEPHDN(ctx, cephName)
	if found {
		slog.Debug("CEPH group already exists", "name", cephName, "cephDN", cephDN)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to find CEPH DN: %w", err)
	}

	gidNumber, err := ld.GetNextGidNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next GID number: %w", err)
	}
	slog.Debug("GID number", "gidNumber", gidNumber)

	allCephsDN := cfg.LDAPCephDN
	slog.Debug("All CEPHs DN", "allCephsDN", allCephsDN)

	slog.Debug("Created CEPH OU", "name", cephName)
	cephFullName, err := getCEPHFullName(ctx, cephName)
	if err != nil {
		return fmt.Errorf("failed to get CEPH full name: %w", err)
	}
	slog.Debug("CEPH group name", "cephName", cephFullName)
	err = ld.CreateGroup(ctx, cephOUDN, cephFullName, gidNumber)
	if err != nil {
		return fmt.Errorf("failed to create CEPH group object: %w", err)
	}
	slog.Debug("Created CEPH group object", "cephName", cephFullName)

	return nil
}

func CephDelete(ctx context.Context, cephName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	cephDN, found, err := findCEPHDN(ctx, cephName)
	if err != nil {
		return fmt.Errorf("failed to find CEPH DN: %w", err)
	}
	if !found {
		slog.Debug("Ceph group not found", "name", cephName)
		return nil
	}
	slog.Debug("Ceph DN", cephDN, err)

	baseDN := cfg.LDAPCephDN
	fullName, err := getCEPHFullName(ctx, cephName)
	if err != nil {
		return fmt.Errorf("failed to obtain Ceph group fullname: %w", err)
	}
	fullNameCN := fmt.Sprintf("cn=%s,%s", fullName, baseDN)
	members, err := ld.GetGroupMemberUsernames(ctx, fullNameCN)
	if err != nil {
		return fmt.Errorf("failed to get group members: %w", err)
	}
	if len(members) > 0 {
		return fmt.Errorf("Ceph group is not empty. There are %d members. Please remove all members and try again", len(members))
	}
	err = ld.DeleteGroup(ctx, cephDN)
	if err != nil {
		return fmt.Errorf("failed to delete CEPH group object: %w", err)
	}
	return nil
}
