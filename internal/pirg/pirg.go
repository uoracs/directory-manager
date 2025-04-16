package pirg

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/lcrownover/directory-manager/internal/config"
	"github.com/lcrownover/directory-manager/internal/keys"
	ld "github.com/lcrownover/directory-manager/internal/ldap"
)

var (
	err   error
	found bool
)

func getUserDN(ctx context.Context, name string) (string, error) {
	dn, err := ld.GetUserDN(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get user DN: %w", err)
	}
	if dn == "" {
		return "", fmt.Errorf("user %s not found", name)
	}
	return dn, nil
}

func getPIRGDN(ctx context.Context, name string) (string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	baseDN := cfg.LDAPPirgDN
	return fmt.Sprintf("OU=%s,%s", name, baseDN), nil
}

func findPIRGDN(ctx context.Context, name string) (string, bool, error) {
	groupName := fmt.Sprintf("is.racs.pirg.%s", name)
	dn, err := ld.GetGroupDN(ctx, groupName)
	if err != nil {
		return "", false, fmt.Errorf("failed to get group DN: %w", err)
	}
	if dn == "" {
		return "", false, nil
	}
	return dn, true, nil
}

func PirgCreate(ctx context.Context, name string, pi string) error {
	slog.Debug("Creating PIRG", "name", name, "pi", pi)

	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}

	// Check if the PIRG already exists
	pirgDN, found, err := findPIRGDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to find PIRG DN: %w", err)
	}
	if found {
		slog.Info("PIRG already exists", "name", name, "pirgDN", pirgDN)
		return nil
	}

	// Get the starting gidNumber, we'll increment locally
	// for each group we create
	gidNumber, err := ld.GetNextGidNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next GID number: %w", err)
	}
	slog.Debug("GID number", "gidNumber", gidNumber)

	allPirgsDN := cfg.LDAPPirgDN
	slog.Debug("All PIRGs DN", "allPirgsDN", allPirgsDN)

	// Create the PIRG OU inside the PIRGS base DN
	err = ld.CreateOU(ctx, allPirgsDN, name)
	if err != nil {
		return fmt.Errorf("failed to create PIRG OU: %w", err)
	}
	slog.Debug("Created PIRG OU", "name", name)

	// Create the PIRG subgroups OU inside the PIRG OU
	pirgDN, err = getPIRGDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	slog.Debug("PIRG DN", "pirgDN", pirgDN)
	err = ld.CreateOU(ctx, pirgDN, "Groups")
	if err != nil {
		return fmt.Errorf("failed to create PIRG subgroups OU: %w", err)
	}
	slog.Debug("Created PIRG subgroups OU", "name", name)

	// Create the PIRG group object
	pirgName := fmt.Sprintf("is.racs.pirg.%s", name)
	slog.Debug("PIRG group name", "pirgName", pirgName)
	err = ld.CreateADGroup(ctx, pirgDN, pirgName, gidNumber)
	if err != nil {
		return fmt.Errorf("failed to create PIRG group object: %w", err)
	}
	slog.Debug("Created PIRG group object", "pirgName", pirgName)

	// Create the PIRG admins group object
	pirgAdminsGroupName := fmt.Sprintf("is.racs.pirg.%s.admins", name)
	slog.Debug("PIRG admins group name", "pirgAdminsGroupName", pirgAdminsGroupName)
	err = ld.CreateADGroup(ctx, pirgDN, pirgAdminsGroupName, gidNumber+1)
	if err != nil {
		return fmt.Errorf("failed to create PIRG admins group object: %w", err)
	}
	slog.Debug("Created PIRG admins group object", "pirgAdminsGroupName", pirgAdminsGroupName)

	// Create the PIRG PI group object
	pirgPIGroupName := fmt.Sprintf("is.racs.pirg.%s.pi", name)
	slog.Debug("PIRG PI group name", "pirgPIGroupName", pirgPIGroupName)
	err = ld.CreateADGroup(ctx, pirgDN, pirgPIGroupName, gidNumber+2)
	if err != nil {
		return fmt.Errorf("failed to create PIRG PI group object: %w", err)
	}
	slog.Debug("Created PIRG PI group object", "pirgPIGroupName", pirgPIGroupName)

	return nil
}

func PirgDelete(ctx context.Context, name string) error {
	// Delete the PIRG with the given name
	// This function should interact with the LDAP server to delete the PIRG.
	return nil
}

func PirgGetPI(ctx context.Context, name string) (string, error) {
	// Get the PI of the PIRG with the given name
	// This function should interact with the LDAP server to get the PI.
	return "", nil
}

func PirgSetPI(ctx context.Context, name string, pi string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	pirgDN, err := getPIRGDN(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get PIRG DN: %w", err)
	}
	userDN, err := getUserDN(ctx, pi)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}
	err = ld.AddUserToGroup(ctx, pirgDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add pi user %s to PIRG %s: %w", pi, name, err)
	}

	return nil
}

func PirgList(ctx context.Context) ([]string, error) {
	// List all PIRGs
	// This function should interact with the LDAP server to list all PIRGs.
	return []string{}, nil
}

func PirgAddMember(ctx context.Context, name string, member string) error {
	// Add a member to the PIRG with the given name
	// This function should interact with the LDAP server to add the member.
	return nil
}

func PirgRemoveMember(ctx context.Context, name string, member string) error {
	// Remove a member from the PIRG with the given name
	// This function should interact with the LDAP server to remove the member.
	return nil
}
func PirgListMembers(ctx context.Context, name string) ([]string, error) {
	// List all members of the PIRG with the given name
	// This function should interact with the LDAP server to list all members.
	return []string{}, nil
}
func PirgListAdmins(ctx context.Context, name string) ([]string, error) {
	// List all admins of the PIRG with the given name
	// This function should interact with the LDAP server to list all admins.
	return []string{}, nil
}
func PirgAddAdmin(ctx context.Context, name string, admin string) error {
	// Add an admin to the PIRG with the given name
	// This function should interact with the LDAP server to add the admin.
	return nil
}
func PirgRemoveAdmin(ctx context.Context, name string, admin string) error {
	// Remove an admin from the PIRG with the given name
	// This function should interact with the LDAP server to remove the admin.
	return nil
}
func PirgSubgroupCreate(ctx context.Context, name string, subgroupName string) error {
	// Create a new subgroup under the PIRG with the given name
	// This function should interact with the LDAP server to create the subgroup.
	return nil
}
func PirgSubgroupDelete(ctx context.Context, name string, subgroupName string) error {
	// Delete the subgroup with the given name under the PIRG
	// This function should interact with the LDAP server to delete the subgroup.
	return nil
}
func PirgSubgroupListMembers(ctx context.Context, name string, subgroupName string) ([]string, error) {
	// List all members of the subgroup with the given name under the PIRG
	// This function should interact with the LDAP server to list all members.
	return []string{}, nil
}
func PirgSubgroupAddMember(ctx context.Context, name string, subgroupName string, member string) error {
	// Add a member to the subgroup with the given name under the PIRG
	// This function should interact with the LDAP server to add the member.
	return nil
}
func PirgSubgroupRemoveMember(ctx context.Context, name string, subgroupName string, member string) error {
	// Remove a member from the subgroup with the given name under the PIRG
	// This function should interact with the LDAP server to remove the member.
	return nil
}
func PirgSubgroupList(ctx context.Context, name string) ([]string, error) {
	// List all subgroups of the PIRG with the given name
	// This function should interact with the LDAP server to list all subgroups.
	return []string{}, nil
}
