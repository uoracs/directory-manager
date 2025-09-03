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
	"github.com/uoracs/directory-manager/internal/ceph"
	"github.com/uoracs/directory-manager/internal/software"
)

var version = "v1.1.1"

var CLI struct {
	Config  string      `help:"Path to the configuration file." short:"c" type:"path"`
	Debug   bool        `help:"Enable debug mode." short:"d" type:"bool"`
	Version VersionFlag `help:"Show version." short:"v" type:"bool"`

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

	Ceph struct {
		List struct {
		} `cmd:"" help:"Get list of all ceph groups."`
		Name struct {
			GetGID struct {} `cmd:"" help:"Create a new CEPH group."`
			GetPI  struct{} `cmd:"" help:"Get the PI of a PIRG."`
			Create struct {} `cmd:"" help:"Create a new CEPH group."`
			SetPI struct {
				PI string `arg:"" name:"username" help:"Names of the PI." type:"name"`
			} `cmd:"" help:"Set the PI of a new CEPH group."`
			Delete struct{} `cmd:"" help:"Delete a CEPH group."`
			Name string `arg:""`
			ListMembers struct{} `cmd:"" help:"List all members of a ceph group."`
			AddMember   struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Add members to a CEPH group."`
			RemoveMember struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Remove members from a PIRG."`
		} `arg:""`
	} `cmd:"" help:"Manage SOFTWARE groups."`
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

	case "ceph list":
		ceph_groups, err := ceph.CephList(ctx)
		if err != nil {
			fmt.Printf("Error obtaining list of all ceph groups: %v\n", err)
			os.Exit(1)
		}
		if len(ceph_groups) == 0 {
			fmt.Println("No Ceph groups found.")
			return
		}
		for _, groups := range ceph_groups{
			fmt.Println(groups)
		}
	case "ceph <name> list-members":
		found, err := ceph.CephExists(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error checking Ceph group existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Ceph %s not found.\n", CLI.Ceph.Name.Name)
			return
		}
		members, err := ceph.CephListMemberUsernames(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error listing members: %v\n", err)
			os.Exit(1)
		}
		for _, member := range members {
			fmt.Println(member)
		}
	case "ceph <name> get-gid":
		gid, err := ceph.CephGroupGID(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error checking CEPH group existence: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(gid)

	case "ceph <name> get-pi":
		piName, err := ceph.CephPiListMemberUsername(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error checking CEPH group existence: %v\n", err)
			os.Exit(1)
		}
		if len(piName) == 0 {
    	    fmt.Println("No PI assigned to this ceph group")
    	} else {
    	    for _, name := range piName {
    	        fmt.Println(name)
    	    }
    	}

	case "ceph <name> set-pi <username>":
		found, err := ceph.CephExists(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error checking CEPH group existence: %v\n", err)
			os.Exit(1)
		}
		if found {
			slog.Debug("CEPH group already exists")
		}
		res := ceph.CephSetPI(ctx, CLI.Ceph.Name.Name, CLI.Ceph.Name.SetPI.PI)
		if res == nil {
			return 
		}
		fmt.Printf("Error setting pi of ceph group: %s\n", res)
		return

	case "ceph <name> create":
		found, err := ceph.CephExists(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error checking CEPH group existence: %v\n", err)
			os.Exit(1)
		}
		if found {
			fmt.Printf("CEPH group %s already exists.\n", CLI.Ceph.Name.Name)
			return
		}
		err = ceph.CephCreate(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error creating Ceph group: %v\n", err)
			os.Exit(1)
		}
	case "ceph <name> delete":
		found, err := ceph.CephExists(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error checking Ceph existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("CEPH group %s not found.\n", CLI.Ceph.Name.Name)
			return
		}
		err = ceph.CephDelete(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error deleting CEPH group: %v\n", err)
			os.Exit(1)
		}
	case "ceph <name> add-member <username>":
		found, err := ceph.CephExists(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error checking PIRG existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("CEPH group %s not found.\n", CLI.Ceph.Name.Name)
			return
		}
		for _, username := range CLI.Ceph.Name.AddMember.Usernames {
			err = ceph.CephAddMember(ctx, CLI.Ceph.Name.Name, username)
			if err != nil {
				fmt.Printf("Error adding member %s: %v\n", username, err)
				os.Exit(1)
			}
		}
	case "ceph <name> remove-member <username>":
		found, err := ceph.CephExists(ctx, CLI.Ceph.Name.Name)
		if err != nil {
			fmt.Printf("Error checking CEPH group existence: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("CEPH group %s not found.\n", CLI.Ceph.Name.Name)
			return
		}
		for _, username := range CLI.Ceph.Name.RemoveMember.Usernames {
			err = ceph.CephRemoveMember(ctx, CLI.Ceph.Name.Name, username)
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
