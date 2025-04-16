package ldap

import (
	"context"
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	"github.com/lcrownover/directory-manager/internal/config"
	"github.com/lcrownover/directory-manager/internal/keys"
)

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
