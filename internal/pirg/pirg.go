package pirg

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/uoracs/directory-manager/internal/config"
	"github.com/uoracs/directory-manager/internal/keys"
	ld "github.com/uoracs/directory-manager/internal/ldap"
)

var (
	err   error
	found bool
)

func getPIRGFullName(ctx context.Context, pirgName string) (string, error) {
	slog.Debug("Getting PIRG full name", "pirgName", pirgName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s%s", cfg.LDAPGroupPrefix, pirgName, cfg.LDAPGroupSuffix)
	slog.Debug("PIRG full name", "name", n)
	return n, nil
}

func getPIRGAdminsGroupFullName(ctx context.Context, pirgName string) (string, error) {
	slog.Debug("Getting PIRG admins group full name", "pirgName", pirgName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s%s.admins", cfg.LDAPGroupPrefix, pirgName, cfg.LDAPGroupSuffix)
	slog.Debug("PIRG admins group full name", "name", n)
	return n, nil
}

func getPIRGPIGroupFullName(ctx context.Context, pirgName string) (string, error) {
	slog.Debug("Getting PIRG PI group full name", "pirgName", pirgName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s%s.pi", cfg.LDAPGroupPrefix, pirgName, cfg.LDAPGroupSuffix)
	slog.Debug("PIRG PI group full name", "name", n)
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
func getPIRGSubgroupOUDN(ctx context.Context, pirgName string) (string, error) {
	slog.Debug("Getting PIRG subgroup OU DN", "pirgName", pirgName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGOUDN(ctx, pirgName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	n := fmt.Sprintf("OU=Groups,%s", pirgDN)
	slog.Debug("PIRG subgroup OU DN", "dn", n)
	return n, nil
}

// getPIRGOUDN returns the DistinguishedName of the PIRG OU with the given name.
// for example: OU=pirg_name,OU=PIRGs,DC=example,DC=com
func getPIRGOUDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting PIRG OU DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	baseDN := cfg.LDAPPirgDN
	n := fmt.Sprintf("OU=%s,%s", name, baseDN)
	slog.Debug("PIRG OU DN", "dn", n)
	return n, nil
}

// getPIRGDN returns the DistinguishedName of the PIRG with the given name.
// if not found, it returns an error.
func getPIRGDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting PIRG DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGOUDN(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	groupName, err := getPIRGFullName(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", groupName, pirgDN)
	slog.Debug("PIRG DN", "dn", n)
	return n, nil
}

// findPIRGDN returns the DistinguishedName of the PIRG with the given name.
// includes a check if the group exists.
// if not found, it returns an empty string, false, and nil
func findPIRGDN(ctx context.Context, name string) (string, bool, error) {
	slog.Debug("Finding PIRG DN", "name", name)
	groupName, err := getPIRGFullName(ctx, name)
	if err != nil {
		return "", false, fmt.Errorf("failed to get PIRG full name: %w", err)
	}
	dn, found, err := ld.GetGroupDN(ctx, groupName)
	if !found && err == nil {
		slog.Debug("PIRG not found", "name", name)
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("failed to get group DN: %w", err)
	}
	slog.Debug("PIRG DN found", "dn", dn)
	return dn, true, nil
}

// getPIRGSubgroupShortName returns the short name of the PIRG subgroup with the given name.
// for example: myprefix.groupname.subgroup_name -> subgroup_name
func getPIRGSubgroupShortName(pirgName string, subgroupName string) string {
	slog.Debug("Getting PIRG subgroup short name", "pirgName", pirgName, "subgroupName", subgroupName)
	parts := strings.Split(subgroupName, ".")
	n := parts[len(parts)-1]
	slog.Debug("PIRG subgroup short name", "name", n)
	return n
}

// getPIRGAdminsGroupDN returns the DistinguishedName of the PIRG Admins group with the given name.
func getPIRGAdminsGroupDN(ctx context.Context, pirgName string) (string, error) {
	slog.Debug("Getting PIRG admins group DN", "pirgName", pirgName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGOUDN(ctx, pirgName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	adminsGroupFullName, err := getPIRGAdminsGroupFullName(ctx, pirgName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG admins group full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", adminsGroupFullName, pirgDN)
	slog.Debug("PIRG admins group DN", "dn", n)
	return n, nil
}

// getPIRGPIGroupDN returns the DistinguishedName of the PIRG PI group with the given name.
func getPIRGPIGroupDN(ctx context.Context, pirgName string) (string, error) {
	slog.Debug("Getting PIRG PI group DN", "pirgName", pirgName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGOUDN(ctx, pirgName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	piGroupFullName, err := getPIRGPIGroupFullName(ctx, pirgName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG PI group full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", piGroupFullName, pirgDN)
	slog.Debug("PIRG PI group DN", "dn", n)
	return n, nil
}

// getPIRGSubgroupDN returns the DistinguishedName of the PIRG subgroup with the given name.
func getPIRGSubgroupDN(ctx context.Context, pirgName string, subgroupName string) (string, error) {
	slog.Debug("Getting PIRG subgroup DN", "pirgName", pirgName, "subgroupName", subgroupName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGOUDN(ctx, pirgName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	subgroupFullName, err := getPIRGSubgroupName(ctx, pirgName, subgroupName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG subgroup full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,OU=Groups,%s", subgroupFullName, pirgDN)
	slog.Debug("PIRG subgroup DN", "dn", n)
	return n, nil
}

// getPIRGSubgroupName returns the name of the PIRG subgroup with the given name.
func getPIRGSubgroupName(ctx context.Context, pirgName string, subgroupName string) ( string, error ) {
	slog.Debug("Getting PIRG subgroup name", "pirgName", pirgName, "subgroupName", subgroupName)
	pirgFullName, err := getPIRGFullName(ctx, pirgName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG full name: %w", err)
	}
	subgroupFullName := fmt.Sprintf("%s.%s", pirgFullName, subgroupName)
	slog.Debug("PIRG subgroup name", "name", subgroupFullName)
	return subgroupFullName, nil
}

// PirgExists checks if the PIRG with the given name exists.
func PirgExists(ctx context.Context, name string) (bool, error) {
	// Check if the PIRG with the given name exists
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	pirgDN, found, err := findPIRGDN(ctx, name)
	if err != nil {
		return false, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	if !found {
		slog.Debug("PIRG not found", "name", name)
		return false, nil
	}
	slog.Debug("PIRG found", "name", name, "pirgDN", pirgDN)
	return true, nil
}

func PirgCreate(ctx context.Context, pirgName string, piUsername string) error {
	slog.Debug("Creating PIRG", "name", pirgName, "pi", piUsername)

	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}

	// Check if the PIRG already exists
	pirgDN, found, err := findPIRGDN(ctx, pirgName)
	if found {
		slog.Debug("PIRG already exists", "name", pirgName, "pirgDN", pirgDN)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to find PIRG DN: %w", err)
	}

	// Get the starting gidNumber, we'll increment locally
	// for each group we create
	// TODO: use the prod version: ld.GetNextGidNumber
	gidNumber, err := ld.GetDummyGidNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next GID number: %w", err)
	}
	slog.Debug("GID number", "gidNumber", gidNumber)

	allPirgsDN := cfg.LDAPPirgDN
	slog.Debug("All PIRGs DN", "allPirgsDN", allPirgsDN)

	// Create the PIRG OU inside the PIRGS base DN
	err = ld.CreateOU(ctx, allPirgsDN, pirgName)
	if err != nil {
		return fmt.Errorf("failed to create PIRG OU: %w", err)
	}
	slog.Debug("Created PIRG OU", "name", pirgName)

	// Create the PIRG subgroups OU inside the PIRG OU
	pirgOUDN, err := getPIRGOUDN(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	slog.Debug("PIRG DN", "pirgOUDN", pirgOUDN)
	err = ld.CreateOU(ctx, pirgOUDN, "Groups")
	if err != nil {
		return fmt.Errorf("failed to create PIRG subgroups OU: %w", err)
	}
	slog.Debug("Created PIRG subgroups OU", "name", pirgName)

	// Create the PIRG group object
	pirgFullName, err := getPIRGFullName(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG full name: %w", err)
	}
	slog.Debug("PIRG group name", "pirgName", pirgFullName)
	err = ld.CreateGroup(ctx, pirgOUDN, pirgFullName, gidNumber)
	if err != nil {
		return fmt.Errorf("failed to create PIRG group object: %w", err)
	}
	slog.Debug("Created PIRG group object", "pirgName", pirgFullName)

	// Create the PIRG admins group object
	pirgAdminsGroupName, err := getPIRGAdminsGroupFullName(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG admins group full name: %w", err)
	}
	slog.Debug("PIRG admins group name", "pirgAdminsGroupName", pirgAdminsGroupName)
	err = ld.CreateGroup(ctx, pirgOUDN, pirgAdminsGroupName, gidNumber+1)
	if err != nil {
		return fmt.Errorf("failed to create PIRG admins group object: %w", err)
	}
	slog.Debug("Created PIRG admins group object", "pirgAdminsGroupName", pirgAdminsGroupName)

	// Create the PIRG PI group object
	pirgPIGroupFullName, err := getPIRGPIGroupFullName(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG PI group full name: %w", err)
	}
	slog.Debug("PIRG PI group name", "pirgPIGroupName", pirgPIGroupFullName)
	err = ld.CreateGroup(ctx, pirgOUDN, pirgPIGroupFullName, gidNumber+2)
	if err != nil {
		return fmt.Errorf("failed to create PIRG PI group object: %w", err)
	}
	slog.Debug("Created PIRG PI group object", "pirgPIGroupName", pirgPIGroupFullName)

	// Add the PI to the PIRG PI group
	err = PirgSetPI(ctx, pirgName, piUsername)
	if err != nil {
		return fmt.Errorf("failed to add PI user %s to PIRG PI group %s: %w", piUsername, pirgName, err)
	}
	slog.Debug("Added PI to PIRG PI group", "piUsername", piUsername, "pirgName", pirgName)

	// Add the PI to the PIRG admins group
	err = PirgAddAdmin(ctx, pirgName, piUsername)
	if err != nil {
		return fmt.Errorf("failed to add PI user %s to PIRG admins group %s: %w", piUsername, pirgName, err)
	}
	slog.Debug("Added PI to PIRG admins group", "piUsername", piUsername, "pirgName", pirgName)

	// Add the PI to the PIRG group
	err = PirgAddMember(ctx, pirgName, piUsername)
	if err != nil {
		return fmt.Errorf("failed to add PI user %s to PIRG %s: %w", piUsername, pirgName, err)
	}
	slog.Debug("Added PI to PIRG group", "piUsername", piUsername, "pirgName", pirgName)

	return nil
}

func PirgDelete(ctx context.Context, pirgName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	pirgOUDN, err := getPIRGOUDN(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	err = ld.DeleteOURecursively(ctx, pirgOUDN)
	if err != nil {
		return fmt.Errorf("failed to delete PIRG group object: %w", err)
	}
	return nil
}

// PirgGetPI returns the PI username for the PIRG with the given name.
func PirgGetPIUsername(ctx context.Context, pirgName string) (string, error) {
	// Get the PI username for the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	pirgPIGroupDN, err := getPIRGPIGroupDN(ctx, pirgName)
	if err != nil {
		return "", fmt.Errorf("failed to get PIRG PI group DN: %w", err)
	}
	members, err := ld.GetGroupMemberUsernames(ctx, pirgPIGroupDN)
	if err != nil {
		return "", fmt.Errorf("failed to get group members: %w", err)
	}
	if len(members) == 0 {
		return "", fmt.Errorf("no PI found for PIRG %s", pirgName)
	}
	if len(members) > 1 {
		return "", fmt.Errorf("multiple PIs found for PIRG %s", pirgName)
	}
	return members[0], nil
}

func PirgSetPI(ctx context.Context, pirgName string, piUsername string) error {
	slog.Debug("Setting PI for PIRG", "pirgName", pirgName, "piUsername", piUsername)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGDN(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	piDN, err := getUserDN(ctx, piUsername)
	if err != nil {
		return fmt.Errorf("failed to get pi DN: %w", err)
	}
	// Remove existing PI from the PIRG PI group
	pirgPIGroupDN, err := getPIRGPIGroupDN(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG PI group DN: %w", err)
	}
	// find existing users in the group
	existingMemberDNs, err := ld.GetGroupMemberDNs(ctx, pirgPIGroupDN)
	if err != nil {
		return fmt.Errorf("failed to get group members: %w", err)
	}
	if len(existingMemberDNs) == 0 {
		slog.Debug("No existing PI found in PIRG PI group", "pirgPIGroupDN", pirgPIGroupDN)
	} else if len(existingMemberDNs) > 1 {
		slog.Debug("Multiple existing PIs found in PIRG PI group", "pirgPIGroupDN", pirgPIGroupDN)
	}
	for _, existingMemberDN := range existingMemberDNs {
		slog.Debug("Removing existing PI from PIRG PI group", "existingMemberDN", existingMemberDN)
		err = ld.RemoveUserFromGroup(ctx, pirgPIGroupDN, existingMemberDN)
		if err != nil {
			return fmt.Errorf("failed to remove existing PI from PIRG PI group: %w", err)
		}
	}
	// Add the user to the PIRG
	err = ld.AddUserToGroup(ctx, pirgDN, piDN)
	if err != nil {
		return fmt.Errorf("failed to add pi user %s to PIRG %s: %w", piUsername, pirgName, err)
	}
	// Add the user to the PIRG PI group
	err = ld.AddUserToGroup(ctx, pirgPIGroupDN, piDN)
	if err != nil {
		return fmt.Errorf("failed to add pi user %s to PIRG PI group %s: %w", piUsername, pirgName, err)
	}

	// Add the user to the admins group
	pirgAdminsGroupDN, err := getPIRGAdminsGroupDN(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG admins group DN: %w", err)
	}
	err = ld.AddUserToGroup(ctx, pirgAdminsGroupDN, piDN)
	if err != nil {
		return fmt.Errorf("failed to add pi user %s to PIRG admins group %s: %w", piUsername, pirgName, err)
	}

	return nil
}

func PirgList(ctx context.Context) ([]string, error) {
	// List all PIRGs
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	allPirgsDN := cfg.LDAPPirgDN
	pirgs, err := ld.GetGroupNamesInOU(ctx, allPirgsDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRGs: %w", err)
	}
	return pirgs, nil
}

func PirgAddMember(ctx context.Context, name string, member string) error {
	// Add a member to the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is already a member of the PIRG
	inGroup, err := ld.UserInGroup(ctx, pirgDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User already in PIRG", "userDN", userDN, "pirgDN", pirgDN)
		return nil
	}

	// Add the user to the PIRG group
	err = ld.AddUserToGroup(ctx, pirgDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to PIRG %s: %w", member, name, err)
	}
	slog.Debug("Added user to PIRG", "userDN", userDN, "pirgDN", pirgDN)
	return nil
}

func PirgRemoveMember(ctx context.Context, name string, member string) error {
	// Remove a member from the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is a member of the PIRG
	inGroup, err := ld.UserInGroup(ctx, pirgDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in PIRG", "userDN", userDN, "pirgDN", pirgDN)
		return nil
	}

	// Remove the user from the PIRG group
	err = ld.RemoveUserFromGroup(ctx, pirgDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from PIRG %s: %w", member, name, err)
	}
	slog.Debug("Removed user from PIRG", "userDN", userDN, "pirgDN", pirgDN)

	// Remove the user from all subgroups of the PIRG
	slog.Debug("Removing user from PIRG subgroups", "userDN", userDN)
	pirgSubgroupOUDN, err := getPIRGSubgroupOUDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroup OU DN: %w", err)
	}
	subgroups, err := ld.GetGroupDNsInOU(ctx, pirgSubgroupOUDN)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroups: %w", err)
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
			return fmt.Errorf("failed to remove user %s from PIRG subgroup %s: %w", member, subgroupDN, err)
		}
	}
	return nil
}

func PirgListMemberUsernames(ctx context.Context, name string) ([]string, error) {
	// List all members of the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGDN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	members, err := ld.GetGroupMemberUsernames(ctx, pirgDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	return members, nil
}

func PirgListMemberDNs(ctx context.Context, name string) ([]string, error) {
	// List all members of the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGDN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	members, err := ld.GetGroupMemberDNs(ctx, pirgDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	return members, nil
}

func PirgListAdminUsernames(ctx context.Context, name string) ([]string, error) {
	// List all admins of the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGDN(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	admins, err := ld.GetGroupMemberUsernames(ctx, pirgDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	return admins, nil
}

// PirgAddAdmin adds an admin to the PIRG with the given name.
func PirgAddAdmin(ctx context.Context, pirgName string, adminUsername string) error {
	// Add an admin to the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	adminGroupDN, err := getPIRGAdminsGroupDN(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG admin group DN: %w", err)
	}
	userDN, err := getUserDN(ctx, adminUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is already an admin of the PIRG
	inGroup, err := ld.UserInGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User already in PIRG admins group", "userDN", userDN, "pirgDN", adminGroupDN)
		return nil
	}

	// Add the user to the PIRG admins group
	err = ld.AddUserToGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add admin %s to PIRG %s: %w", adminUsername, pirgName, err)
	}
	slog.Debug("Added admin to PIRG", "userDN", userDN, "pirgDN", adminGroupDN)
	return nil
}

// PirgRemoveAdmin removes an admin from the PIRG with the given name.
func PirgRemoveAdmin(ctx context.Context, pirgName string, adminUsername string) error {
	// Remove an admin from the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	adminGroupDN, err := getPIRGAdminsGroupDN(ctx, pirgName)
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
		slog.Debug("User not in PIRG admins group", "userDN", userDN, "pirgDN", adminGroupDN)
		return nil
	}

	// Remove the user from the PIRG admins group
	err = ld.RemoveUserFromGroup(ctx, adminGroupDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove admin %s from PIRG %s: %w", adminUsername, pirgName, err)
	}
	slog.Debug("Removed admin from PIRG", "userDN", userDN, "pirgDN", adminGroupDN)
	return nil
}

// PirgSubgroupExists checks if the subgroup with the given name exists under the PIRG.
func PirgSubgroupExists(ctx context.Context, pirgName string, subgroupName string) (bool, error) {
	// Check if the subgroup with the given name exists under the PIRG
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getPIRGSubgroupDN(ctx, pirgName, subgroupName)
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
func PirgSubgroupList(ctx context.Context, pirgName string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	pirgSubgroupsOUDN, err := getPIRGSubgroupOUDN(ctx, pirgName)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroup OU DN: %w", err)
	}
	subgroups, err := ld.GetGroupNamesInOU(ctx, pirgSubgroupsOUDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroups: %w", err)
	}
	shortNames := make([]string, len(subgroups))
	for i, subgroup := range subgroups {
		shortNames[i] = getPIRGSubgroupShortName(pirgName, subgroup)
	}

	return shortNames, nil
}

// PirgSubgroupCreate creates a new subgroup under the PIRG with the given name.
func PirgSubgroupCreate(ctx context.Context, pirgName string, subgroupName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getPIRGSubgroupDN(ctx, pirgName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroup DN: %w", err)
	}
	subgroupOUDN, err := getPIRGSubgroupOUDN(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroup OU DN: %w", err)
	}

	subgroupFullName, err := getPIRGSubgroupName(ctx, pirgName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroup full name: %w", err)
	}

	// Create the subgroup object inside the PIRG OU/Groups
	gidNumber, err := ld.GetDummyGidNumber(ctx)
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
func PirgSubgroupDelete(ctx context.Context, pirgName string, subgroupName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getPIRGSubgroupDN(ctx, pirgName, subgroupName)
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
func PirgSubgroupListMemberUsernames(ctx context.Context, pirgName string, subgroupName string) ([]string, error) {
	// List all members of the subgroup with the given name under the PIRG
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getPIRGSubgroupDN(ctx, pirgName, subgroupName)
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
	return members, nil
}

// PirgSubgroupListMemberDNs lists all members of the subgroup with the given name under the PIRG.
func PirgSubgroupListMemberDNs(ctx context.Context, pirgName string, subgroupName string) ([]string, error) {
	// List all members of the subgroup with the given name under the PIRG
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getPIRGSubgroupDN(ctx, pirgName, subgroupName)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroup DN: %w", err)
	}
	members, err := ld.GetGroupMemberDNs(ctx, subgroupDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	return members, nil
}

// PirgSubgroupAddMember adds a member to the subgroup with the given name under the PIRG.
func PirgSubgroupAddMember(ctx context.Context, pirgName string, subgroupName string, memberUsername string) error {
	// Check if memberUsername is in the PIRG
	pirgDN, err := getPIRGDN(ctx, pirgName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	userDN, err := getUserDN(ctx, memberUsername)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}
	inGroup, err := ld.UserInGroup(ctx, pirgDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		return fmt.Errorf("user %s is not a member of the PIRG %s", memberUsername, pirgName)
	}

	// Add a member to the subgroup with the given name under the PIRG
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getPIRGSubgroupDN(ctx, pirgName, subgroupName)
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
func PirgSubgroupRemoveMember(ctx context.Context, pirgName string, subgroupName string, memberUsername string) error {
	// Remove a member from the subgroup with the given name under the PIRG
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	subgroupDN, err := getPIRGSubgroupDN(ctx, pirgName, subgroupName)
	if err != nil {
		return fmt.Errorf("failed to get PIRG subgroup DN: %w", err)
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
func PirgSubgroupListNames(ctx context.Context, pirgName string) ([]string, error) {
	// List all subgroups of the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	pirgOUDN, err := getPIRGOUDN(ctx, pirgName)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	subgroupsDN := fmt.Sprintf("OU=Groups,%s", pirgOUDN)
	subgroups, err := ld.GetGroupNamesInOU(ctx, subgroupsDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroups: %w", err)
	}
	return subgroups, nil
}

// PirgSubgroupListDNs lists all subgroup DNs of the PIRG with the given name.
func PirgSubgroupListDNs(ctx context.Context, pirgName string) ([]string, error) {
	// List all subgroups of the PIRG with the given name
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	pirgOUDN, err := getPIRGOUDN(ctx, pirgName)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	subgroupsDN := fmt.Sprintf("OU=Groups,%s", pirgOUDN)
	subgroups, err := ld.GetGroupDNsInOU(ctx, subgroupsDN)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIRG subgroups: %w", err)
	}
	return subgroups, nil
}
