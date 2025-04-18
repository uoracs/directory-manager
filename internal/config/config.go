package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/goccy/go-yaml"
)

type Config struct {
	LDAPServer       string `yaml:"ldap_server"`
	LDAPPort         int    `yaml:"ldap_port"`
	LDAPUsername     string `yaml:"ldap_username"`
	LDAPPassword     string `yaml:"ldap_password"`
	LDAPUsersBaseDN  string `yaml:"ldap_users_base_dn"`
	LDAPGroupsBaseDN string `yaml:"ldap_groups_base_dn"`
	LDAPPirgDN       string `yaml:"ldap_pirg_dn"`
	LDAPCephDN       string `yaml:"ldap_ceph_dn"`
	LDAPMinGid       int    `yaml:"ldap_min_gid"`
	LDAPMaxGid       int    `yaml:"ldap_max_gid"`
	LDAPGroupPrefix  string `yaml:"ldap_group_prefix"`
	LDAPGroupSuffix  string `yaml:"ldap_group_suffix"`
	DataPath         string `yaml:"data_path"`
}

func loadEnvironment() (*Config, error) {
	slog.Debug("Loading environment variables")
	var err error
	var c Config
	var found bool

	c.LDAPServer, found = os.LookupEnv("DIRECTORY_MANAGER_LDAP_SERVER")
	if found {
		slog.Debug("Found LDAP server in environment variables")
	}
	port, found := os.LookupEnv("DIRECTORY_MANAGER_LDAP_PORT")
	if found {
		slog.Debug("Found LDAP port in environment variables")
		c.LDAPPort, err = strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("failed to convert LDAP port to int: %w", err)
		}
	}
	c.LDAPUsername, found = os.LookupEnv("DIRECTORY_MANAGER_LDAP_USERNAME")
	if found {
		slog.Debug("Found LDAP username in environment variables")
	}
	c.LDAPPassword, found = os.LookupEnv("DIRECTORY_MANAGER_LDAP_PASSWORD")
	if found {
		slog.Debug("Found LDAP password in environment variables")
	}
	c.LDAPUsersBaseDN, found = os.LookupEnv("DIRECTORY_MANAGER_LDAP_USERS_BASE_DN")
	if found {
		slog.Debug("Found LDAP users base DN in environment variables")
	}
	c.LDAPGroupsBaseDN, found = os.LookupEnv("DIRECTORY_MANAGER_LDAP_GROUPS_BASE_DN")
	if found {
		slog.Debug("Found LDAP groups base DN in environment variables")
	}
	c.LDAPPirgDN, found = os.LookupEnv("DIRECTORY_MANAGER_LDAP_PIRG_DN")
	if found {
		slog.Debug("Found LDAP PIRG DN in environment variables")
	}
	c.LDAPCephDN, found = os.LookupEnv("DIRECTORY_MANAGER_LDAP_CEPH_DN")
	if found {
		slog.Debug("Found LDAP Ceph DN in environment variables")
	}
	mingid, found := os.LookupEnv("DIRECTORY_MANAGER_LDAP_MIN_GID")
	if found {
		slog.Debug("Found LDAP min gid in environment variables")
		c.LDAPMinGid, err = strconv.Atoi(mingid)
		if err != nil {
			return nil, fmt.Errorf("failed to convert LDAP min gid to int: %w", err)
		}
	}
	maxgid, found := os.LookupEnv("DIRECTORY_MANAGER_LDAP_MAX_GID")
	if found {
		slog.Debug("Found LDAP max gid in environment variables")
		c.LDAPMaxGid, err = strconv.Atoi(maxgid)
		if err != nil {
			return nil, fmt.Errorf("failed to convert LDAP max gid to int: %w", err)
		}
	}
	c.LDAPGroupPrefix, found = os.LookupEnv("DIRECTORY_MANAGER_LDAP_GROUP_PREFIX")
	if found {
		slog.Debug("Found LDAP group prefix in environment variables")
	}
	c.LDAPGroupSuffix, found = os.LookupEnv("DIRECTORY_MANAGER_LDAP_GROUP_SUFFIX")
	if found {
		slog.Debug("Found LDAP group suffix in environment variables")
	}
	dataPath, found := os.LookupEnv("DIRECTORY_MANAGER_DATA_PATH")
	if found {
		slog.Debug("Found data path in environment variables")
		c.DataPath = dataPath
	}
	return &c, nil
}

func readConfig(path string) (*Config, error) {
	// Open the YAML file
	yml, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Decode the YAML file into the Config struct
	var c Config
	if err := yaml.Unmarshal(yml, &c); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return &c, nil
}

func mergeConfigsLeft(cfg1, cfg2 *Config) *Config {
	if cfg1 == nil {
		return cfg2
	}
	if cfg2 == nil {
		return cfg1
	}

	if cfg2.LDAPServer != "" {
		cfg1.LDAPServer = cfg2.LDAPServer
	}
	if cfg2.LDAPPort != 0 {
		cfg1.LDAPPort = cfg2.LDAPPort
	}
	if cfg2.LDAPUsername != "" {
		cfg1.LDAPUsername = cfg2.LDAPUsername
	}
	if cfg2.LDAPPassword != "" {
		cfg1.LDAPPassword = cfg2.LDAPPassword
	}
	if cfg2.LDAPUsersBaseDN != "" {
		cfg1.LDAPUsersBaseDN = cfg2.LDAPUsersBaseDN
	}
	if cfg2.LDAPGroupsBaseDN != "" {
		cfg1.LDAPGroupsBaseDN = cfg2.LDAPGroupsBaseDN
	}
	if cfg2.LDAPPirgDN != "" {
		cfg1.LDAPPirgDN = cfg2.LDAPPirgDN
	}
	if cfg2.LDAPCephDN != "" {
		cfg1.LDAPCephDN = cfg2.LDAPCephDN
	}
	if cfg2.LDAPMinGid != 0 {
		cfg1.LDAPMinGid = cfg2.LDAPMinGid
	}
	if cfg2.LDAPMaxGid != 0 {
		cfg1.LDAPMaxGid = cfg2.LDAPMaxGid
	}
	if cfg2.LDAPGroupPrefix != "" {
		cfg1.LDAPGroupPrefix = cfg2.LDAPGroupPrefix
	}
	if cfg2.LDAPGroupSuffix != "" {
		cfg1.LDAPGroupSuffix = cfg2.LDAPGroupSuffix
	}
	if cfg2.DataPath != "" {
		cfg1.DataPath = cfg2.DataPath
	}

	return cfg1
}

func GetConfig(path string) (*Config, error) {
	var err error
	var fileCfg *Config
	if path != "" {
		fileCfg, err = readConfig(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}
	envCfg, err := loadEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}
	cfg := mergeConfigsLeft(fileCfg, envCfg)

	// Set unconfigurable values


	// Validate the config values and set defaults
	if cfg.LDAPServer == "" {
		return nil, fmt.Errorf("ldap_server is required")
	}
	if cfg.LDAPPort == 0 {
		cfg.LDAPPort = 686
	}
	if cfg.LDAPUsername == "" {
		return nil, fmt.Errorf("ldap_username is required")
	}
	if cfg.LDAPPassword == "" {
		return nil, fmt.Errorf("ldap_password is required")
	}
	if cfg.LDAPUsersBaseDN == "" {
		return nil, fmt.Errorf("ldap_users_base_dn is required")
	}
	if cfg.LDAPGroupsBaseDN == "" {
		return nil, fmt.Errorf("ldap_groups_base_dn is required")
	}
	if cfg.LDAPPirgDN == "" {
		return nil, fmt.Errorf("ldap_pirg_dn is required")
	}
	if cfg.LDAPCephDN == "" {
		return nil, fmt.Errorf("ldap_ceph_dn is required")
	}
	if cfg.LDAPMinGid == 0 {
		return nil, fmt.Errorf("ldap_min_gid is required")
	}
	if cfg.LDAPMaxGid == 0 {
		return nil, fmt.Errorf("ldap_max_gid is required")
	}
	if cfg.LDAPMinGid >= cfg.LDAPMaxGid {
		return nil, fmt.Errorf("ldap_min_gid must be less than ldap_max_gid")
	}
	if cfg.DataPath == "" {
		cfg.DataPath = "/var/lib/directory-manager"
	}

	return cfg, nil
}
