// package cache
//
// import (
// 	"bytes"
// 	"context"
// 	"encoding/gob"
// 	"fmt"
// 	"os"
//
// 	"github.com/lcrownover/directory-manager/internal/config"
// 	"github.com/lcrownover/directory-manager/internal/keys"
// 	ld "github.com/lcrownover/directory-manager/internal/ldap"
// )
//
// type GidCache struct {
// 	ctx context.Context
// 	cacheFilePath string
// 	existing map[string]int
// }
//
// func NewGidCache(ctx context.Context) *GidCache {
// 	cfg := ctx.Value(keys.ConfigKey).(*config.Config)
// 	if cfg == nil {
// 		panic("config not found in context")
// 	}
// 	cacheFilePath := cfg.DataPath + "/cache.bin"
// 	return &GidCache{
// 		ctx:     ctx,
// 		cacheFilePath: cacheFilePath,
// 		existing: make(map[string]int),
// 	}
// }
//
// func (c *GidCache) GidNumber(groupname string) (int, bool) {
// 	gid, found := c.existing[groupname]
// 	return gid, found
// }
//
// func (c *GidCache) Register(groupname string, gid int) {
// 	c.existing[groupname] = gid
// 	err := c.Save()
// 	if err != nil {
// 		fmt.Printf("failed to save cache: %v\n", err)
// 	}
// }
//
// // NextGid returns the next available GID number.
// // It doesn't get the next _available_ GID number, but the next GID number after 
// // the highest one in the cache.
// func (c *GidCache) NextGid(groupname string) (int, error) {
// 	if _, found := c.existing[groupname]; found {
// 		return 0, fmt.Errorf("group %s already exists in cache", groupname)
// 	}
// 	highestGid := 0
// 	if len(c.existing) == 0 {
// 		return 0, fmt.Errorf("cache is empty")
// 	}
// 	for _, gid := range c.existing {
// 		if gid > highestGid {
// 			highestGid = gid
// 		}
// 	}
//
// 	newGid := highestGid + 1
// 	return newGid, nil
// }
//
// func (c *GidCache) Clear() {
// 	c.existing = make(map[string]int)
// 	c.Save()
// }
//
// func (c *GidCache) Rebuild() error {
// 	c.Clear()
// 	m, err := ld.GetExistingGroupsWithGidNumbers(c.ctx)
// 	if err != nil {
// 		return fmt.Errorf("failed to get existing groups with gid numbers: %w", err)
// 	}
// 	c.existing = m
// 	return nil
// }
// func (c *GidCache) Save() error {
// 	b := new(bytes.Buffer)
// 	enc := gob.NewEncoder(b)
// 	err := enc.Encode(c.existing)
// 	if err != nil {
// 		return fmt.Errorf("failed to encode cache: %w", err)
// 	}
// 	err = os.WriteFile(c.cacheFilePath, b.Bytes(), 0600)
// 	if err != nil {
// 		return fmt.Errorf("failed to write cache to file: %w", err)
// 	}
// 	return nil
// }
//
// func (c *GidCache) Load() error {
// 	if _, err := os.Stat(c.cacheFilePath); os.IsNotExist(err) {
// 		c.existing = make(map[string]int)
// 		return nil
// 	}
// 	b, err := os.ReadFile(c.cacheFilePath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read cache file: %w", err)
// 	}
// 	dec := gob.NewDecoder(bytes.NewReader(b))
// 	err = dec.Decode(&c.existing)
// 	if err != nil {
// 		return fmt.Errorf("failed to decode cache: %w", err)
// 	}
// 	return nil
// }
//
// func (c *GidCache) Print() {
// 	fmt.Println("Current Gid Cache:")
// 	for groupname, gid := range c.existing {
// 		fmt.Printf("Group: %s, GID: %d\n", groupname, gid)
// 	}
// }
//
