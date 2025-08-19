package software 

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
	groupPrefix           = "is.racs.software."
	topLevelUsersGroupDN  = "CN=IS.RACS.Talapas.Users,OU=RACS,OU=Groups,OU=IS,OU=Units,DC=ad,DC=uoregon,DC=edu"
)

func ConvertSoftwareGroupNametoShortName(swName string) (string, error) {
	slog.Debug("Converting Software group name to short name", "swName", swName)
	parts := strings.Split(swName, ".")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid SOFTWARE group name: %s", swName)
	}
	shortName := parts[len(parts)-1]
	slog.Debug("Converted SOFTWARE group name to short name", "shortName", shortName)
	return shortName, nil
}

func SoftwareGroupNameRegex(ctx context.Context) (string, error) {

	// Initialize the SOFTWARE group name regex
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	swGroupNameRegex := fmt.Sprintf("^%s([a-zA-Z0-9_\\-]+)$", groupPrefix)
	slog.Debug("Software group name regex", "regex", swGroupNameRegex)
	return swGroupNameRegex, nil
}

func findSWDN(ctx context.Context, name string) (string, bool, error) {
	slog.Debug("Finding SW DN", "name", name)
	groupName, err := getSOFTWAREFullName(ctx, name)
	if err != nil {
		return "", false, fmt.Errorf("failed to get SOFTWARE full name: %w", err)
	}
	dn, found, err := ld.GetGroupDN(ctx, groupName)
	if !found && err == nil {
		slog.Debug("SOFTWARE group not found", "name", name)
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("failed to get group DN: %w", err)
	}
	slog.Debug("SOFTWARE DN found", "dn", dn)
	return dn, true, nil
}

func SoftwareExists(ctx context.Context, name string) (bool, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return false, fmt.Errorf("config not found in context")
	}
	swDN, found, err := findSWDN(ctx, name)
	if err != nil {
		return false, fmt.Errorf("failed to get SOFTWARE DN: %w", err)
	}
	if !found {
		slog.Debug("SOFTWARE not found", "name", name)
		return false, nil
	}
	slog.Debug("SOFTWARE found", "name", name, "swDN", swDN)
	return true, nil
}

func SoftwareList(ctx context.Context) ([]string, error) {
	// List all Software 
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}
	allSoftwareDN := cfg.LDAPSoftwareDN
	software_groups, err := ld.GetGroupNamesInOU(ctx, allSoftwareDN, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get Software  groups: %w", err)
	}
	softwareGroupNameRegex, err := SoftwareGroupNameRegex(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Software  group name regex: %w", err)
	}
	var softwareGroupNames []string
	for _, sw := range software_groups {
		if matched, err := regexp.MatchString(softwareGroupNameRegex, sw); err != nil {
			return nil, fmt.Errorf("failed to match Software group name regex: %w", err)
		} else if matched {
			softwareGroupNames = append(softwareGroupNames, sw)
		}
	}
	var softwareShortNames []string
	for _, sw := range softwareGroupNames {
		shortName, err := ConvertSoftwareGroupNametoShortName(sw)
		if err != nil {
			return nil, fmt.Errorf("failed to convert Software group name to short name: %w", err)
		}
		softwareShortNames = append(softwareShortNames, shortName)
	}
	slices.Sort(softwareShortNames)
	slog.Debug("SOFTWARE names", "softwareShortNames", softwareShortNames)
	return softwareShortNames, nil
}

func getSWDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting SOFTWARE DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	swDN, err := getSWOUDN(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get SOFTWARE DN: %w", err)
	}
	groupName, err := getSOFTWAREFullName(ctx, name)
	if err != nil {
		return "", fmt.Errorf("failed to get SOFTWARE full name: %w", err)
	}
	n := fmt.Sprintf("CN=%s,%s", groupName, swDN)

	slog.Debug("SOFTWARE DN", "dn", n)
	return n, nil
}

func getSOFTWAREFullName(ctx context.Context, swName string) (string, error) {
	slog.Debug("Getting SOFTWARE group full name", "swName", swName)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	n := fmt.Sprintf("%s%s", groupPrefix, swName)
	slog.Debug("SOFTWARE full name", "name", n)
	return n, nil
}

func getSWOUDN(ctx context.Context, name string) (string, error) {
	slog.Debug("Getting SOFTWARE OU DN", "name", name)
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return "", fmt.Errorf("config not found in context")
	}
	baseDN := cfg.LDAPSoftwareDN
	slog.Debug("SOFTWARE OU DN", "dn", baseDN)
	
	return baseDN, nil
}

func SoftwareListMemberUsernames(ctx context.Context, name string) ([]string, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return nil, fmt.Errorf("config not found in context")
	}

	fullName, err := getSOFTWAREFullName(ctx, name)

	baseDN := cfg.LDAPSoftwareDN
	if err != nil {
		return nil, fmt.Errorf("failed to get SOFTWARE DN: %w", err)
	}
	fullNameCN := fmt.Sprintf("cn=%s,%s",fullName, baseDN)
	members, err := ld.GetGroupMemberUsernames(ctx, fullNameCN)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	slices.Sort(members)
	return members, nil
}
func SoftwareAddMember(ctx context.Context, softwareName string, member string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	softwareDN, err := getSWDN(ctx, softwareName)
	if err != nil {
		return fmt.Errorf("failed to get SOFTWARE DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	// Check if the user is already a member of the SOFTWARE group
	inGroup, err := ld.UserInGroup(ctx, softwareDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if inGroup {
		slog.Debug("User already in SOFTWARE group", "userDN", userDN, "softwareDN", softwareDN)
		return nil
	}

	slog.Debug("Adding user to SOFTWARE", "userDN", userDN, "softwareDN", softwareDN)
	err = ld.AddUserToGroup(ctx, softwareDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to add user %s to SOFTWARE %s: %w", member, softwareName, err)
	}
	slog.Debug("Added user to SOFTWARE", "userDN", userDN, "SOFTWAREDN", softwareDN)

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
func SoftwareRemoveMember(ctx context.Context, name string, member string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	softwareDN, err := getSWDN(ctx, name)
	// fmt.Println("softwareDN maybe not:", softwareDN)
	if err != nil {
		return fmt.Errorf("failed to get SOFTWARE DN: %w", err)
	}
	userDN, err := getUserDN(ctx, member)
	if err != nil {
		return fmt.Errorf("failed to get user DN: %w", err)
	}

	inGroup, err := ld.UserInGroup(ctx, softwareDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to check if user is in group: %w", err)
	}
	if !inGroup {
		slog.Debug("User not in SOFTWARE group", "userDN", userDN, "softwareDN", softwareDN)
		return nil
	}
	err = ld.RemoveUserFromGroup(ctx, softwareDN, userDN)
	if err != nil {
		return fmt.Errorf("failed to remove user %s from SOFTWARE %s: %w", member, name, err)
	}
	slog.Debug("Removed user from SOFTWARE", "userDN", userDN, "softwareDN", softwareDN)

	return nil
}
func SoftwareCreate(ctx context.Context, softwareName string) error {
	slog.Debug("Creating software group", "name", softwareName)

	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}

	softwareOUDN, err := getSWOUDN(ctx, softwareName)
	if err != nil {
		return fmt.Errorf("failed to get software OUDN : %w", err)
	}
	// Check if the software already exists
	softwareDN, found, err := findSWDN(ctx, softwareName)
	if found {
		slog.Debug("software group already exists", "name", softwareName, "softwareDN", softwareDN)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to find software DN: %w", err)
	}

	gidNumber, err := ld.GetNextGidNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get next GID number: %w", err)
	}
	slog.Debug("GID number", "gidNumber", gidNumber)

	allsoftwaresDN := cfg.LDAPSoftwareDN
	slog.Debug("All softwares DN", "allsoftwaresDN", allsoftwaresDN)

	slog.Debug("Created software OU", "name", softwareName)
	softwareFullName, err := getSOFTWAREFullName(ctx, softwareName)
	if err != nil {
		return fmt.Errorf("failed to get software full name: %w", err)
	}
	slog.Debug("software group name", "softwareName", softwareFullName)
	err = ld.CreateGroup(ctx, softwareOUDN, softwareFullName, gidNumber)
	if err != nil {
		return fmt.Errorf("failed to create software group object: %w", err)
	}
	slog.Debug("Created software group object", "softwareName", softwareFullName)

	return nil
}

func SoftwareDelete(ctx context.Context, softwareName string) error {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return fmt.Errorf("config not found in context")
	}
	softwareDN, found, err := findSWDN(ctx, softwareName)
	if err != nil {
		return fmt.Errorf("failed to find Software DN: %w", err)
	}
	if !found {
		slog.Debug("software group not found", "name", softwareName)
		return nil
	}
	slog.Debug("software DN", softwareDN, err)

	baseDN := cfg.LDAPSoftwareDN
	fullName, err := getSOFTWAREFullName(ctx, softwareName)
	if err != nil {
		return fmt.Errorf("failed to obtain software group fullname: %w", err)
	}
	fullNameCN := fmt.Sprintf("cn=%s,%s", fullName, baseDN)
	members, err := ld.GetGroupMemberUsernames(ctx, fullNameCN)
	if err != nil {
		return fmt.Errorf("failed to get group members: %w", err)
	}
	if len(members) > 0 {
		return fmt.Errorf("software group is not empty. There are %d members. Please remove all members and try again", len(members))
	}
	err = ld.DeleteGroup(ctx, softwareDN)
	if err != nil {
		return fmt.Errorf("failed to delete software group object: %w", err)
	}
	return nil
}

