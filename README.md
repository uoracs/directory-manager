# directory-manager

This tool simplifies automating our complicated LDAP group structure for RACS at UO.

## Installing

Either [download the latest release](https://github.com/uoracs/directory-manager/releases), or install with `go` by running `go install github.com/uoracs/directory-manager@latest`.

## Configuration

There's a bit of configuration you need to specify, either via a configuration file in YAML format, or by setting the relevant environment variables.

You can find an example `config.yaml.example` [in the repository](https://github.com/uoracs/directory-manager/blob/main/config.yaml.example).

All of these settings can also be set via corresponding environment variables:

```bash
export DIRECTORY_MANAGER_LDAP_SERVER="my-ldap-server.org"
export DIRECTORY_MANAGER_LDAP_USERNAME=""
export DIRECTORY_MANAGER_LDAP_PASSWORD=""
export DIRECTORY_MANAGER_LDAP_USERS_BASE_DN="dc=company,dc=org"
export DIRECTORY_MANAGER_LDAP_GROUPS_BASE_DN="ou=Groups,dc=company,dc=org"
export DIRECTORY_MANAGER_LDAP_PIRG_DN="ou=PIRGS,ou=Groups,dc=company,dc=org"
export DIRECTORY_MANAGER_LDAP_CEPH_DN="ou=Ceph,ou=Groups,dc=company,dc=org"
export DIRECTORY_MANAGER_LDAP_MIN_GID=50000
export DIRECTORY_MANAGER_LDAP_MAX_GID=60000
export DIRECTORY_MANAGER_LDAP_GROUP_PREFIX="myorg.research.pirg."
export DIRECTORY_MANAGER_LDAP_GROUP_SUFFIX=""
```
