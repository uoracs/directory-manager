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
export DIRECTORY_MANAGER_LDAP_CEPH_DN="ou=CEPH,ou=Groups,dc=company,dc=org"
export DIRECTORY_MANAGER_LDAP_SOFTWARE_DN="ou=SOFTWARE,ou=Groups,dc=company,dc=org"
export DIRECTORY_MANAGER_LDAP_MIN_GID=50000
export DIRECTORY_MANAGER_LDAP_MAX_GID=60000
export DIRECTORY_MANAGER_LDAP_GROUP_PREFIX="myorg.research.pirg."
export DIRECTORY_MANAGER_LDAP_GROUP_SUFFIX=""
```

## Pushing new releases: 

If you partake in any new development with this tool, utilize goreleaser to push new releases to github

## IMPORTANT: Setting up a Github TOKEN

We need to give goreleaser a GitHub token to use to access our release uploads. 
You can create a new token here: *https://github.com/settings/tokens/new* if you're signed in. 
You'll need to give it the "repo" permissions (just check the box of the whole section) . Name the token something useful 
(like goreleaser, etc), and copy the value you're given and in your terminal, add this token value to your environment
variables with the name GITHUB_TOKEN. See below:
```bash
$ export GITHUB_TOKEN=token_string
``` 
I also recommend adding it into you ~/.zshrc or similar stucture file for pernament and consistent loading of any custom env variables. 

### Steps: 

- rm -rf dist/
- git tag vX.Y.Z
- goreleaser
