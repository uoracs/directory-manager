package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/go-ldap/ldap/v3"
	"github.com/uoracs/directory-manager/internal/config"
	"github.com/uoracs/directory-manager/internal/keys"
	ld "github.com/uoracs/directory-manager/internal/ldap"
	"github.com/uoracs/directory-manager/internal/pirg"
	"github.com/uoracs/directory-manager/internal/cephfs"
	"github.com/uoracs/directory-manager/internal/cephs3"
	"github.com/uoracs/directory-manager/internal/software"
)

var version = "v1.1.5"

var CLI struct {
	Config  string      `help:"Path to the configuration file." short:"c" type:"path"`
	Debug   bool        `help:"Enable debug mode." short:"d" type:"bool"`
	Version VersionFlag `help:"Show version." short:"v" type:"bool"`

	Aduser struct {
		Name struct {
			Name string `arg:""`
				GetUid  struct{} `cmd:"" help:"Get the UID of a User in AD."`
				RemoveTalapasGroupUser  struct{} `cmd:"" help:"Remove the user from the main Talapas group"`
				AddTalapasGroupUser  struct{} `cmd:"" help:"Remove the user from the main Talapas group"`
		} `arg:""`
	} `cmd:"" help:"Manage PIRGs."`
	Pirg struct {
		List struct {
		} `cmd:"" help:"List all PIRGs."`
		Name struct {
			Name string `arg:""`

			Create struct {
				PI string `required:"" help:"Name of the PI." type:"name"`
			} `cmd:"" help:"Create a new PIRG."`
			Delete struct{} `cmd:"" help:"Delete a PIRG."`
			GetPI  struct{} `cmd:"" help:"Get the PI of a PIRG."`
			SetPI  struct {
				PI string `required:"" name:"pi" help:"Name of the PI." type:"name"`
			} `cmd:"" help:"Set the PI of a PIRG."`
			ListMembers struct{} `cmd:"" help:"List all members of a PIRG."`
			AddMember   struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Add members to a PIRG."`
			RemoveMember struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Remove members from a PIRG."`
			ListAdmins struct{} `cmd:"" help:"List all admins of a PIRG."`
			AddAdmin   struct {
				Usernames []string `arg:"" name:"username" help:"Names of the admins." type:"name"`
			} `cmd:"" help:"Add admins to a PIRG."`
			RemoveAdmin struct {
				Usernames []string `arg:"" name:"username" help:"Names of the admins." type:"name"`
			} `cmd:"" help:"Remove admins from a PIRG."`
			Subgroup struct {
				List struct{} `cmd:"" help:"List all subgroups."`
				Name struct {
					Name        string   `arg`
					Create      struct{} `cmd:"" help:"Create a new subgroup."`
					Delete      struct{} `cmd:"" help:"Delete a subgroup."`
					ListMembers struct{} `cmd:"" help:"List all members of a subgroup."`
					AddMember   struct {
						Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
					} `cmd:"" help:"Add members to a subgroup."`
					RemoveMember struct {
						Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
					} `cmd:"" help:"Remove members from a subgroup."`
				} `arg`
			} `cmd:"" help:"Manage subgroups."`
		} `arg:""`
	} `cmd:"" help:"Manage PIRGs."`

	Nextgidnumber struct {
	} `cmd:"" help:"Get the next available GID number in the specified range."`

	Cephs3 struct {
		List struct {
		} `cmd:"" help:"Get list of all cephs3 groups."`
		Name struct {
			Name string `arg:""`
			GetGID struct {} `cmd:"" help:"Get the GID of a cephs3 group."`
			GetOwner  struct{} `cmd:"" help:"Get the Owner of a cephs3 group."`
			SetOwner  struct {
				Owner string `required:"" help:"Name of the Owner." type:"name"`
			} `cmd:"" help:"Set the Owner of a cephs3 group."`
			Create struct {
				Owner string `required:"" help:"Name of the Owner." type:"name"`
			} `cmd:"" help:"Create a new cephs3 group."`
			Delete struct{} `cmd:"" help:"Delete a cephs3 group."`
			ListMembers struct{} `cmd:"" help:"List all members of a cephs3 group."`
			AddMember   struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Add members to a cephs3 group."`
			RemoveMember struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Remove members from a cephs3 group."`
		} `arg:""`
	} `cmd:"" name:"cephs3" help:"Manage Ceph s3 buckets groups."`
	Cephfs struct {
		List struct {
		} `cmd:"" help:"Get list of all cephfs groups."`
		Name struct {
			Name string `arg:""`
			GetGID struct {} `cmd:"" help:"Get the GID of a cephfs group."`
			GetOwner  struct{} `cmd:"" help:"Get the Owner of a cephfs group."`
			SetOwner  struct {
				Owner string `required:"" help:"Name of the Owner." type:"name"`
			} `cmd:"" help:"Set the Owner of a cephfs group."`
			Create struct {
				Owner string `required:"" help:"Name of the Owner." type:"name"`
			} `cmd:"" help:"Create a new cephfs group."`
			Delete struct{} `cmd:"" help:"Delete a cephfs group."`
			ListMembers struct{} `cmd:"" help:"List all members of a cephfs group."`
			AddMember   struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Add members to a cephfs group."`
			RemoveMember struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Remove members from a cephfs group."`
		} `arg:""`
	} `cmd:"" help:"Manage Cephfs POSIX groups."`
	Software struct {
		List struct {
		} `cmd:"" help:"Get list of all software groups."`
		Name struct {
			Create struct {} `cmd:"" help:"Create a new SOFTWARE."`
			Delete struct{} `cmd:"" help:"Delete a SOFTWARE."`
			Name string `arg:""`
			ListMembers struct{} `cmd:"" help:"List all members of a software group."`
			AddMember   struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Add members to a SOFTWARE group."`
			RemoveMember struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Remove members from a SOFTWARE Group."`
		} `arg:""`
	} `cmd:"" help:"Manage SOFTWARE groups."`
}

type VersionFlag bool

func (v VersionFlag) BeforeReset(app *kong.Kong, vars kong.Vars) error {
	fmt.Fprintln(app.Stdout, vars["version"])
	app.Exit(0)
	return nil
}

func main() {
	cli := kong.Parse(&CLI,
		kong.Name("directory-manager"),
		kong.Description("Command-line tool for managing HPC ActiveDirectory groups."),
		kong.Vars{"version": version},
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}))

	if CLI.Version {
		fmt.Printf("Version: %s\n", version)
		os.Exit(0)
	}

	// Set up logging
	slogOpts := slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	if CLI.Debug {
		slogOpts = slog.HandlerOptions{
			Level: slog.LevelDebug,
		}
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slogOpts)))
	slog.Debug("Debug mode enabled")

	cfg, err := config.GetConfig(CLI.Config)
	slog.Debug("Loading config", "path", CLI.Config)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}
	slog.Debug("Loaded config", "config", cfg)
	ctx := context.Background()
	ctx = context.WithValue(ctx, keys.ConfigKey, cfg)

	// Initialize the LDAP connection
	ctx, err = ld.LoadLDAPConnection(ctx)
	if err != nil {
		fmt.Printf("Error loading LDAP connection: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		l := ctx.Value(keys.LDAPConnKey).(*ldap.Conn)
		if l != nil {
			err := l.Close()
			if err != nil {
				fmt.Printf("Error closing LDAP connection: %v\n", err)
			}
		}
	}()
	slog.Debug("Loaded LDAP connection")

	switch cli.Command() {
	case "pirg list":
		pirgs, err := pirg.PirgList(ctx)
		if err != nil {
			fmt.Printf("Error listing PIRGs: %v\n", err)
			os.Exit(1)
		}
		if len(pirgs) == 0 {
			fmt.Println("No PIRGs found.")
			return
		}
		for _, pirg := range pirgs {
			fmt.Println(pirg)
		}
	case "pirg <name> create":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if found {
			fmt.Printf("PIRG %s already exists.\n", CLI.Pirg.Name.Name)
			return
		}
		err = pirg.PirgCreate(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Create.PI)
		if err != nil {
			fmt.Printf("Error creating PIRG: %v\n", err)
			os.Exit(1)
		}
	case "pirg <name> delete":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		err = pirg.PirgDelete(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error deleting PIRG: %v\n", err)
			os.Exit(1)
		}
	case "pirg <name> get-pi":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		pi, err := pirg.PirgGetPIUsername(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error getting PI: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(pi)
	case "pirg <name> set-pi":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		err = pirg.PirgSetPI(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.SetPI.PI)
		if err != nil {
			fmt.Printf("Error setting PI: %v\n", err)
			os.Exit(1)
		}
	case "pirg <name> list-members":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		members, err := pirg.PirgListMemberUsernames(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error listing members: %v\n", err)
			os.Exit(1)
		}
		for _, member := range members {
			fmt.Println(member)
		}
	case "pirg <name> add-member <username>":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		for _, username := range CLI.Pirg.Name.AddMember.Usernames {
			err = pirg.PirgAddMember(ctx, CLI.Pirg.Name.Name, username)
			if err != nil {
				fmt.Printf("Error adding member %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "pirg <name> remove-member <username>":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		for _, username := range CLI.Pirg.Name.RemoveMember.Usernames {
			err = pirg.PirgRemoveMember(ctx, CLI.Pirg.Name.Name, username)
			if err != nil {
				fmt.Printf("Error removing member %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "pirg <name> list-admins":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		admins, err := pirg.PirgListAdminUsernames(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error listing admins: %v\n", err)
			os.Exit(1)
		}
		for _, admin := range admins {
			fmt.Println(admin)
		}
	case "pirg <name> add-admin <username>":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		for _, username := range CLI.Pirg.Name.AddAdmin.Usernames {
			err = pirg.PirgAddAdmin(ctx, CLI.Pirg.Name.Name, username)
			if err != nil {
				fmt.Printf("Error adding admin %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "pirg <name> remove-admin <username>":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		for _, username := range CLI.Pirg.Name.RemoveAdmin.Usernames {
			err = pirg.PirgRemoveAdmin(ctx, CLI.Pirg.Name.Name, username)
			if err != nil {
				fmt.Printf("Error removing admin %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "pirg <name> subgroup list":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		subgroups, err := pirg.PirgSubgroupList(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error listing subgroups: %v\n", err)
			os.Exit(1)
		}
		if len(subgroups) == 0 {
			fmt.Println("No subgroups found.")
			return
		}
		for _, subgroup := range subgroups {
			fmt.Println(subgroup)
		}

	case "pirg <name> subgroup <name> create":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		found, err = pirg.PirgSubgroupExists(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Subgroup.Name.Name)
		if err != nil {
			fmt.Printf("Error checking subgroup existence: %v\n", err)
			os.Exit(1)
		}
		if found {
			fmt.Printf("Subgroup %s already exists.\n", CLI.Pirg.Name.Subgroup.Name.Name)
			return
		}
		err = pirg.PirgSubgroupCreate(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Subgroup.Name.Name)
		if err != nil {
			slog.Error("Error creating subgroup", "error", err)
			os.Exit(1)
		}
	case "pirg <name> subgroup <name> delete":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		found, err = pirg.PirgSubgroupExists(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Subgroup.Name.Name)
		if err != nil {
			fmt.Printf("Error checking subgroup existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Subgroup %s not found.\n", CLI.Pirg.Name.Subgroup.Name.Name)
			return
		}
		err = pirg.PirgSubgroupDelete(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Subgroup.Name.Name)
		if err != nil {
			fmt.Printf("Error deleting subgroup: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Subgroup %s not found.\n", CLI.Pirg.Name.Subgroup.Name.Name)
			return
		}
	case "pirg <name> subgroup <name> list-members":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		found, err = pirg.PirgSubgroupExists(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Subgroup.Name.Name)
		if err != nil {
			fmt.Printf("Error checking subgroup existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Subgroup %s not found.\n", CLI.Pirg.Name.Subgroup.Name.Name)
			return
		}
		members, err := pirg.PirgSubgroupListMemberUsernames(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Subgroup.Name.Name)
		if err != nil {
			fmt.Printf("Error listing subgroup members: %v\n", err)
			os.Exit(1)
		}
		if len(members) == 0 {
			fmt.Println("No members found in subgroup.")
			return
		}
		for _, member := range members {
			fmt.Println(member)
		}
	case "pirg <name> subgroup <name> add-member <username>":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		found, err = pirg.PirgSubgroupExists(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Subgroup.Name.Name)
		if err != nil {
			fmt.Printf("Error checking subgroup existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Subgroup %s not found.\n", CLI.Pirg.Name.Subgroup.Name.Name)
			return
		}
		for _, username := range CLI.Pirg.Name.Subgroup.Name.AddMember.Usernames {
			err = pirg.PirgSubgroupAddMember(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Subgroup.Name.Name, username)
			if err != nil {
				fmt.Printf("Error adding member %s to subgroup: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "pirg <name> subgroup <name> remove-member <username>":
		found, err := pirg.PirgExists(ctx, CLI.Pirg.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("PIRG %s not found.\n", CLI.Pirg.Name.Name)
			return
		}
		found, err = pirg.PirgSubgroupExists(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Subgroup.Name.Name)
		if err != nil {
			fmt.Printf("Error checking subgroup existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Subgroup %s not found.\n", CLI.Pirg.Name.Subgroup.Name.Name)
			return
		}
		for _, username := range CLI.Pirg.Name.Subgroup.Name.RemoveMember.Usernames {
			err = pirg.PirgSubgroupRemoveMember(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Subgroup.Name.Name, username)
			if err != nil {
				fmt.Printf("Error removing member %s from subgroup: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "nextgidnumber":
		gid, err := ld.GetNextGidNumber(ctx)
		if err != nil {
			fmt.Printf("Error obtaining next gid number: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(gid)

	case "aduser <name> get-uid":
		uid, err := ld.GetUidOfExistingUser(ctx, CLI.Aduser.Name.Name)
		if err != nil {
			fmt.Printf("Error obtaining uid for user: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(uid)

	case "aduser <name> remove-talapas-group-user":
		removed_user, err := ld.RemoveUserFromTalapasMaster(ctx, CLI.Aduser.Name.Name)
		if err != nil {
			fmt.Printf("Error removing user from Talapas group (is.racs.talapas.users): %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s", removed_user)

	case "aduser <name> add-talapas-group-user":
		added_user, err := ld.AddUserToTalapasMaster(ctx, CLI.Aduser.Name.Name)
		if err != nil {
			fmt.Printf("Error adding user to Talapas group (is.racs.talapas.users): %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s", added_user)

	case "cephfs list":
		cephfs_groups, err := cephfs.CephfsList(ctx)
		if err != nil {
			fmt.Printf("Error obtaining list of all cephfs groups: %v\n", err)
			os.Exit(1)
		}
		if len(cephfs_groups) == 0 {
			fmt.Println("No cephfs groups found.")
			return
		}
		for _, groups := range cephfs_groups{
			fmt.Println(groups)
		}

	case "cephfs <name> list-members":
		found, err := cephfs.CephfsExists(ctx, CLI.Cephfs.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephfs group existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("cephfs %s not found.\n", CLI.Cephfs.Name.Name)
			return
		}
		members, err := cephfs.CephfsListMemberUsernames(ctx, CLI.Cephfs.Name.Name)
		if err != nil {
			fmt.Printf("Error listing members: %v\n", err)
			os.Exit(1)
		}
		for _, member := range members {
			fmt.Println(member)
		}
	case "cephfs <name> get-gid":
		gid, err := cephfs.GetCephfsGroupGID(ctx, CLI.Cephfs.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephfs group existence: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(gid)

	case "cephfs <name> get-owner":
		ownerName, err := cephfs.CephfsGetOwnerUsername(ctx, CLI.Cephfs.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephfs group existence: %v\n", err)
			os.Exit(1)
		}
		if len(ownerName) == 0 {
	   	    fmt.Println("No PI assigned to this cephfs group")
	   	} else {
			fmt.Println(ownerName)
	   	}

	case "cephfs <name> set-owner":
		found, err := cephfs.CephfsExists(ctx, CLI.Cephfs.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephfs group existence: %v\n", err)
			os.Exit(1)
		}
		if found {
			slog.Debug("cephfs group already exists")
		}
		res := cephfs.CEPHFSSetOWNER(ctx, CLI.Cephfs.Name.Name, CLI.Cephfs.Name.SetOwner.Owner)
		if res == nil {
			return 
		}
		fmt.Printf("Error setting pi of cephs3 group: %s\n", res)
		return

	case "cephfs <name> create":
		found, err := cephfs.CephfsExists(ctx, CLI.Cephfs.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephfs group existence: %v\n", err)
			os.Exit(1)
		}
		if found {
			fmt.Printf("cephfs group %s already exists.\n", CLI.Cephfs.Name.Name)
			return
		}
		err = cephfs.CephfsCreate(ctx, CLI.Cephfs.Name.Name, CLI.Cephfs.Name.Create.Owner)
		if err != nil {
			fmt.Printf("Error creating cephfs group: %v\n", err)
			os.Exit(1)
		}
	case "cephfs <name> delete":
		found, err := cephfs.CephfsExists(ctx, CLI.Cephfs.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephfs existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("cephfs group %s not found.\n", CLI.Cephfs.Name.Name)
			return
		}
		err = cephfs.CephfsDelete(ctx, CLI.Cephfs.Name.Name)
		if err != nil {
			fmt.Printf("Error deleting cephfs group: %v\n", err)
			os.Exit(1)
		}
	case "cephfs <name> add-member <username>":
		found, err := cephfs.CephfsExists(ctx, CLI.Cephfs.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("cephfs group %s not found.\n", CLI.Cephfs.Name.Name)
			return
		}
		for _, username := range CLI.Cephfs.Name.AddMember.Usernames {
			err = cephfs.CephfsAddMember(ctx, CLI.Cephfs.Name.Name, username)
			if err != nil {
				fmt.Printf("Error adding member %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "cephfs <name> remove-member <username>":
		found, err := cephfs.CephfsExists(ctx, CLI.Cephfs.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephfs group existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("cephfs group %s not found.\n", CLI.Cephfs.Name.Name)
			return
		}
		for _, username := range CLI.Cephfs.Name.RemoveMember.Usernames {
			err = cephfs.CephfsRemoveMember(ctx, CLI.Cephfs.Name.Name, username)
			if err != nil {
				fmt.Printf("Error removing member %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "cephs3 list":
		cephs3_groups, err := cephs3.Cephs3List(ctx)
		if err != nil {
			fmt.Printf("Error obtaining list of all cephs3 groups: %v\n", err)
			os.Exit(1)
		}
		if len(cephs3_groups) == 0 {
			fmt.Println("No cephs3 groups found.")
			return
		}
		for _, groups := range cephs3_groups{
			fmt.Println(groups)
		}

	case "cephs3 <name> list-members":
		found, err := cephs3.Cephs3Exists(ctx, CLI.Cephs3.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephs3 group existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("cephs3 %s not found.\n", CLI.Cephs3.Name.Name)
			return
		}
		members, err := cephs3.Cephs3ListMemberUsernames(ctx, CLI.Cephs3.Name.Name)
		if err != nil {
			fmt.Printf("Error listing members: %v\n", err)
			os.Exit(1)
		}
		for _, member := range members {
			fmt.Println(member)
		}
	case "cephs3 <name> get-gid":
		gid, err := cephs3.GetCephs3GroupGID(ctx, CLI.Cephs3.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephs3 group existence: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(gid)

	case "cephs3 <name> get-owner":
		ownerName, err := cephs3.Cephs3GetOwnerUsername(ctx, CLI.Cephs3.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephs3 group existence: %v\n", err)
			os.Exit(1)
		}
		if len(ownerName) == 0 {
	   	    fmt.Println("No PI assigned to this cephs3 group")
	   	} else {
			fmt.Println(ownerName)
	   	}

	case "cephs3 <name> set-owner":
		found, err := cephs3.Cephs3Exists(ctx, CLI.Cephs3.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephs3 group existence: %v\n", err)
			os.Exit(1)
		}
		if found {
			slog.Debug("cephs3 group already exists")
		}
		res := cephs3.Cephs3SetOWNER(ctx, CLI.Cephs3.Name.Name, CLI.Cephs3.Name.SetOwner.Owner)
		if res == nil {
			return 
		}
		fmt.Printf("Error setting pi of cephs3 group: %s\n", res)
		return

	case "cephs3 <name> create":
		found, err := cephs3.Cephs3Exists(ctx, CLI.Cephs3.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephs3 group existence: %v\n", err)
			os.Exit(1)
		}
		if found {
			fmt.Printf("cephs3 group %s already exists.\n", CLI.Cephs3.Name.Name)
			return
		}
		err = cephs3.Cephs3Create(ctx, CLI.Cephs3.Name.Name, CLI.Cephs3.Name.Create.Owner)
		if err != nil {
			fmt.Printf("Error creating cephs3 group: %v\n", err)
			os.Exit(1)
		}
	case "cephs3 <name> delete":
		found, err := cephs3.Cephs3Exists(ctx, CLI.Cephs3.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephs3 existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("cephs3 group %s not found.\n", CLI.Cephs3.Name.Name)
			return
		}
		err = cephs3.Cephs3Delete(ctx, CLI.Cephs3.Name.Name)
		if err != nil {
			fmt.Printf("Error deleting cephs3 group: %v\n", err)
			os.Exit(1)
		}
	case "cephs3 <name> add-member <username>":
		found, err := cephs3.Cephs3Exists(ctx, CLI.Cephs3.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("cephs3 group %s not found.\n", CLI.Cephs3.Name.Name)
			return
		}
		for _, username := range CLI.Cephs3.Name.AddMember.Usernames {
			err = cephs3.Cephs3AddMember(ctx, CLI.Cephs3.Name.Name, username)
			if err != nil {
				fmt.Printf("Error adding member %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "cephs3 <name> remove-member <username>":
		found, err := cephs3.Cephs3Exists(ctx, CLI.Cephs3.Name.Name)
		if err != nil {
			fmt.Printf("Error checking cephs3 group existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("cephs3 group %s not found.\n", CLI.Cephs3.Name.Name)
			return
		}
		for _, username := range CLI.Cephs3.Name.RemoveMember.Usernames {
			err = cephs3.Cephs3RemoveMember(ctx, CLI.Cephs3.Name.Name, username)
			if err != nil {
				fmt.Printf("Error removing member %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "software list":
		software_groups, err := software.SoftwareList(ctx)
		if err != nil {
			fmt.Printf("Error obtaining list of all Software groups: %v\n", err)
			os.Exit(1)
		}
		if len(software_groups) == 0 {
			fmt.Println("No Software groups found.")
			return
		}
		for _, groups := range software_groups{
			fmt.Println(groups)
		}
	case "software <name> list-members":
		found, err := software.SoftwareExists(ctx, CLI.Software.Name.Name)
		if err != nil {
			fmt.Printf("Error checking Software group existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Software %s not found.\n", CLI.Software.Name.Name)
			return
		}
		members, err := software.SoftwareListMemberUsernames(ctx, CLI.Software.Name.Name)
		if err != nil {
			fmt.Printf("Error listing members: %v\n", err)
			os.Exit(1)
		}
		for _, member := range members {
			fmt.Println(member)
		}
	case "software <name> add-member <username>":
		found, err := software.SoftwareExists(ctx, CLI.Software.Name.Name)
		if err != nil {
			fmt.Printf("Error checking SOFTWARE existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("SOFTWARE group %s not found.\n", CLI.Software.Name.Name)
			return
		}
		for _, username := range CLI.Software.Name.AddMember.Usernames {
			err = software.SoftwareAddMember(ctx, CLI.Software.Name.Name, username)
			if err != nil {
				fmt.Printf("Error adding member %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "software <name> remove-member <username>":
		found, err := software.SoftwareExists(ctx, CLI.Software.Name.Name)
		if err != nil {
			fmt.Printf("Error checking SOFTWARE group existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("SOFTWARE group %s not found.\n", CLI.Software.Name.Name)
			return
		}
		for _, username := range CLI.Software.Name.RemoveMember.Usernames {
			err = software.SoftwareRemoveMember(ctx, CLI.Software.Name.Name, username)
			if err != nil {
				fmt.Printf("Error removing member %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "software <name> create":
		found, err := software.SoftwareExists(ctx, CLI.Software.Name.Name)
		if err != nil {
			fmt.Printf("Error checking software group existence: %v\n", err)
			os.Exit(1)
		}
		if found {
			fmt.Printf("software group %s already exists.\n", CLI.Software.Name.Name)
			return
		}
		err = software.SoftwareCreate(ctx, CLI.Software.Name.Name)
		if err != nil {
			fmt.Printf("Error creating software group: %v\n", err)
			os.Exit(1)
		}
	case "software <name> delete":
		found, err := software.SoftwareExists(ctx, CLI.Software.Name.Name)
		if err != nil {
			fmt.Printf("Error checking software existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("software group %s not found.\n", CLI.Software.Name.Name)
			return
		}
		err = software.SoftwareDelete(ctx, CLI.Software.Name.Name)
		if err != nil {
			fmt.Printf("Error deleting software group: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", cli.Command())
		os.Exit(1)
	}
}
