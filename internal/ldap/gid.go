package ldap

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	"github.com/uoracs/directory-manager/internal/config"
	"github.com/uoracs/directory-manager/internal/keys"
)

func GetDummyGidNumber(ctx context.Context) (int, error) {
	n, err := GetNextGidNumber(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get next GID number: %w", err)
	}
	return n + 1000, nil
}

func GetNextGidNumber(ctx context.Context) (int, error) {
	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
	if cfg == nil {
		return 0, fmt.Errorf("config not found in context")
	}
	l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
	if l == nil {
		return 0, fmt.Errorf("LDAP connection not found in context")
	}
	highestGid := 0
	searchRequest := ldap.NewSearchRequest(
		cfg.LDAPGroupsBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=group)(gidNumber=*))",
		[]string{"gidNumber"},
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return 0, fmt.Errorf("failed to search LDAP: %w", err)


	}
	for _, entry := range sr.Entries {
		gid, err := strconv.Atoi(entry.GetAttributeValue("gidNumber"))
		if err != nil {
			continue
		}
		if gid > highestGid {
			highestGid = gid
		}
	}
	if highestGid >= cfg.LDAPMaxGid {
		return 0, fmt.Errorf("no available GID numbers")
	}
	nextGid := highestGid + 1
	if nextGid < cfg.LDAPMinGid {
		return 0, fmt.Errorf("next GID number is less than minimum GID number")
	}
	return nextGid, nil
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

