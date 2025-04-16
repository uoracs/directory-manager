package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/go-ldap/ldap/v3"
	"github.com/lcrownover/directory-manager/internal/config"
	"github.com/lcrownover/directory-manager/internal/keys"
	ld "github.com/lcrownover/directory-manager/internal/ldap"
	"github.com/lcrownover/directory-manager/internal/pirg"
)

var CLI struct {
	Config string `help:"Path to the configuration file." type:"path"`
	Debug bool   `help:"Enable debug mode."`

	Pirg struct {
		List struct {
		} `cmd:"" help:"List all PIRGs."`
		Name struct {
			Name string `arg:""`

			Create struct {
				PI string `required:"" help:"Name of the PI." type:"name"`
			} `cmd:"" help:"Create a new PIRG."`
			Delete struct { } `cmd:"" help:"Delete a PIRG."`
			GetPI struct { } `cmd:"" help:"Get the PI of a PIRG."`
			SetPI struct {
				PI string `required:"" name:"pi" help:"Name of the PI." type:"name"`
			} `cmd:"" help:"Set the PI of a PIRG."`
			ListMembers struct { } `cmd:"" help:"List all members of a PIRG."`
			AddMember struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Add members to a PIRG."`
			RemoveMember struct {
				Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
			} `cmd:"" help:"Remove members from a PIRG."`
			ListAdmins struct { } `cmd:"" help:"List all admins of a PIRG."`
			AddAdmin struct {
				Usernames []string `arg:"" name:"username" help:"Names of the admins." type:"name"`
			} `cmd:"" help:"Add admins to a PIRG."`
			RemoveAdmin struct {
				Usernames []string `arg:"" name:"username" help:"Names of the admins." type:"name"`
			} `cmd:"" help:"Remove admins from a PIRG."`
			Subgroup struct {
				List struct { } `cmd:"" help:"List all subgroups."`
				Name struct {
					Name string `arg`
					Create struct { } `cmd:"" help:"Create a new subgroup."`
					Delete struct { } `cmd:"" help:"Delete a subgroup."`
					ListMembers struct { } `cmd:"" help:"List all members of a subgroup."`
					AddMember struct {
						Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
					} `cmd:"" help:"Add members to a subgroup."`
					RemoveMember struct {
						Usernames []string `arg:"" name:"username" help:"Names of the members." type:"name"`
					} `cmd:"" help:"Remove members from a subgroup."`
				} `arg`

			} `cmd:"" help:"Manage subgroups."`
		} `arg:""`
	} `cmd:"" help:"Manage PIRGs."`
}

func main() {

	cli := kong.Parse(&CLI,
		kong.Name("directory-manager"),
		kong.Description("Command-line tool for managing HPC ActiveDirectory groups."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}))

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
	case "pirg <name> create":
		err = pirg.PirgCreate(ctx, CLI.Pirg.Name.Name, CLI.Pirg.Name.Create.PI)
		if err != nil {
			fmt.Printf("Error creating PIRG: %v\n", err)
			os.Exit(1)
		}
	case "pirg <name> delete":
		fmt.Printf("Deleting PIRG with name: %s\n", CLI.Pirg.Name.Name)
	case "pirg <name> get-pi":
		fmt.Printf("Getting PI of PIRG with name: %s\n", CLI.Pirg.Name.Name)
	case "pirg <name> set-pi":
		fmt.Printf("Setting PI of PIRG with name: %s to %s\n", CLI.Pirg.Name.Name, CLI.Pirg.Name.SetPI.PI)
	case "pirg <name> list-members":
		fmt.Printf("Listing members of PIRG with name: %s\n", CLI.Pirg.Name.Name)
	case "pirg <name> add-member <username>":
		fmt.Printf("Adding members %v to PIRG with name: %s\n", CLI.Pirg.Name.AddMember.Usernames, CLI.Pirg.Name.Name)
	case "pirg <name> remove-member <username>":
		fmt.Printf("Removing members %v from PIRG with name: %s\n", CLI.Pirg.Name.RemoveMember.Usernames, CLI.Pirg.Name.Name)
	case "pirg <name> list-admins":
		fmt.Printf("Listing admins of PIRG with name: %s\n", CLI.Pirg.Name.Name)
	case "pirg <name> add-admin <username>":
		fmt.Printf("Adding admins %v to PIRG with name: %s\n", CLI.Pirg.Name.AddAdmin.Usernames, CLI.Pirg.Name.Name)
	case "pirg <name> remove-admin <username>":
		fmt.Printf("Removing admins %v from PIRG with name: %s\n", CLI.Pirg.Name.RemoveAdmin.Usernames, CLI.Pirg.Name.Name)
	case "pirg <name> subgroup <name> create":
		fmt.Printf("Creating a new subgroup with name: %s under PIRG: %s\n", CLI.Pirg.Name.Subgroup.Name, CLI.Pirg.Name.Name)
	case "pirg <name> subgroup <name> delete":
		fmt.Printf("Deleting subgroup with name: %s under PIRG: %s\n", CLI.Pirg.Name.Subgroup.Name, CLI.Pirg.Name.Name)
	case "pirg <name> subgroup <name> list-members":
		fmt.Printf("Listing members of subgroup with name: %s under PIRG: %s\n", CLI.Pirg.Name.Subgroup.Name, CLI.Pirg.Name.Name)
	case "pirg <name> subgroup <name> add-member <username>":
		fmt.Printf("Adding members %v to subgroup with name: %s under PIRG: %s\n", CLI.Pirg.Name.Subgroup.Name.AddMember.Usernames, CLI.Pirg.Name.Subgroup.Name.Name, CLI.Pirg.Name.Name)
	case "pirg <name> subgroup <name> remove-member <username>":
		fmt.Printf("Removing members %v from subgroup with name: %s under PIRG: %s\n", CLI.Pirg.Name.Subgroup.Name.RemoveMember.Usernames, CLI.Pirg.Name.Subgroup.Name, CLI.Pirg.Name.Name)
	}
}
