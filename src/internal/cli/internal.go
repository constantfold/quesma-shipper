package cli

import (
	"cmp"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/identity"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

func serviceCmd() *cobra.Command {
	cmd := verb("service", "Remove or show how to restart the background service", (*cobra.Command).Help)
	cmd.AddCommand(
		verb("uninstall", "Unload and delete the service entry", func(cmd *cobra.Command) error {
			kind, err := packaging.UninstallService()
			if packaging.RemovalUnverified(err) {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v\n", err)
				return nil
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s service removed\n", kind)
			return nil
		}),
		verb("restart", "Print the command that restarts the service", func(cmd *cobra.Command) error {
			if c := packaging.RestartCommand(); c != "" {
				fmt.Fprintln(cmd.OutOrStdout(), c)
			}
			return nil
		}))
	return cmd
}

func postinstallCmd() *cobra.Command {
	return verb("postinstall", "", func(cmd *cobra.Command) error {
		warning, err := app.PostInstallPackage()
		printWarning(cmd.ErrOrStderr(), warning)
		return err
	})
}

func reportRemote(w io.Writer, r *app.Runtime) {
	rem := r.Remote()
	if rem.Err != nil && rem.Origin == controlplane.OriginCached {
		fmt.Fprintf(w, "warning: using the cached config: %v\n", rem.Err)
	}
	if rem.Err != nil && rem.Origin == controlplane.OriginNone {
		fmt.Fprintf(w, "warning: no remote config in force: %v\n", rem.Err)
	}
	if rem.Expired {
		fmt.Fprintf(w, "warning: the cached config is past its expiry; collecting under it and stamping config_expired\n")
	}
}

func previewCmd(build app.Build) *cobra.Command {
	var sourceFilter string
	cmd := verb("preview", "Show what would be sent, without sending or recording anything", func(cmd *cobra.Command) error {
		env, err := app.New(build)
		if err != nil {
			return err
		}
		if sourceFilter != "" {
			env.FilterSources(sourceFilter)
		}
		rep, err := env.Flush(cmd.Context(), true)
		if err != nil {
			return err
		}
		printPreview(cmd.OutOrStdout(), rep, env)
		return nil
	})
	cmd.Flags().StringVar(&sourceFilter, "source", "", "one source only")
	return cmd
}

func logCmd() *cobra.Command {
	var lines int
	cmd := verb("log", "Recent audit entries: what was decided about each file", func(cmd *cobra.Command) error {
		_, paths, err := app.ResolveEffective()
		if err != nil {
			return err
		}
		log, err := auditlog.Open(paths.StateDir)
		if err != nil {
			return err
		}
		entries, err := auditlog.Tail(log.Path(), lines)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "no entries yet")
			return nil
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		defer w.Flush()
		fmt.Fprintf(w, "WHEN\tDECISION\tSOURCE\tIN\tOUT\tDENSITY\tDETAIL\n")
		for _, e := range entries {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%.4f\t%s\n", e.At.Local().Format("15:04:05"), e.Decision, e.SourceID,
				e.BytesIn, e.BytesOut, e.RedactionDensity, cmp.Or(e.Reason, e.File))
		}
		return nil
	})
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "how many entries")
	return cmd
}

func configCmd() *cobra.Command {
	var withProvenance bool
	cmd := verb("config", "The effective configuration and where each value came from", func(cmd *cobra.Command) error {
		eff, paths, err := app.ResolveEffective()
		if err != nil {
			return err
		}
		printEffective(cmd.OutOrStdout(), eff, paths, withProvenance)
		return nil
	})
	cmd.Flags().BoolVar(&withProvenance, "with-provenance", false, "name the layer that set each value")
	return cmd
}

func printEffective(out io.Writer, eff *config.Effective, paths config.Paths, withProvenance bool) {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	defer w.Flush()
	row := func(field, value string) {
		if !withProvenance {
			fmt.Fprintf(w, "%s\t%s\n", field, value)
			return
		}
		origin := "(not set)"
		if o, ok := eff.Provenance[field]; ok {
			origin = o.Layer.String()
			if o.Derived {
				origin = "derived"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", field, value, origin)
	}
	head := "FIELD\tVALUE"
	if withProvenance {
		head += "\tSET BY"
	}
	fmt.Fprintln(w, head)
	if path, ok := config.UserConfigFound(paths); ok {
		fmt.Fprintf(w, "(config file)\t%s\t%s\n", path, config.LayerUser)
	} else {
		fmt.Fprintf(w, "(config files)\tnone - compiled defaults and bundled catalog only\n")
	}
	row("config_version", fmt.Sprint(eff.ConfigVersion))
	row("organization", eff.OrganizationID)
	row("mode.schedule", eff.Schedule)
	row("max_files_per_run", fmt.Sprint(eff.MaxFilesPerRun))
	row("state_dir", eff.StateDir)
	row("send.sink", config.SinkAdapter)
	for i, t := range eff.UploadTargets {
		row(fmt.Sprintf("upload_targets[%d]", i), t.Origin+" ("+t.Addressing+t.PathPrefix+")")
	}
	row("scrub.rule_packs", strings.Join(eff.RulePacks, ", "))
	row("encryption.include_install_recipient", fmt.Sprint(eff.IncludeInstallRecipient))
	if len(eff.AdditionalRecipients) > 0 {
		row("encryption.additional_recipients", strings.Join(eff.AdditionalRecipients, ", "))
	}
	row("autoupdate.enabled", fmt.Sprint(eff.AutoupdateEnabled))
	for _, s := range eff.Sources {
		key := "sources." + s.ID + "."
		state := "enabled"
		if !s.Enabled {
			state = "disabled"
		}
		row(key+"enabled", state)
		row(key+"root", cmp.Or(s.Root, "(unresolved: "+cmp.Or(s.RootUnresolvedReason, "no candidate root resolved")+")"))
		row(key+"include", strings.Join(s.Include, ", "))
		row(key+"artifact_class", s.ArtifactClass)
		row(key+"spec_fingerprint", s.SpecFingerprint[:16]+"...")
	}
	fmt.Fprintf(w, "\t\t\n")
	fmt.Fprintf(w, "(deny patterns)\t%d compiled + served additions, applied post-expansion and post-symlink\n", len(eff.Deny.Patterns()))
}

func stateCmd() *cobra.Command {
	var apply bool
	// edit is a verb that changes the local record, a dry run unless --apply.
	edit := func(use, short, done string, change func(stateDir, installID string, dryRun bool) (removed, kept int, err error)) *cobra.Command {
		c := verb(use, short, func(cmd *cobra.Command) error {
			_, paths, err := app.ResolveEffective()
			if err != nil {
				return err
			}
			unit, err := identity.Load(paths.StateDir)
			if err != nil {
				return err
			}
			removed, kept, err := change(paths.StateDir, unit.InstallID.String(), !apply)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			switch {
			case removed == 0:
				fmt.Fprintf(w, "nothing to do (%d entries)\n", kept)
			case apply:
				fmt.Fprintf(w, "%d entries %s, %d remain\n", removed, done, kept)
			default:
				fmt.Fprintf(w, "%d entries would be %s; re-run with --apply\n", removed, done)
			}
			return nil
		})
		c.Flags().BoolVar(&apply, "apply", false, "write the change instead of reporting it")
		return c
	}
	cmd := verb("state", "Inspect and repair the local record of what was sent", (*cobra.Command).Help)
	cmd.AddCommand(
		edit("reset", "Forget everything so the next run re-hashes every file and asks the archive what it already holds", "forgotten",
			func(stateDir, installID string, dryRun bool) (int, int, error) {
				removed, err := engine.Reset(stateDir, installID, dryRun)
				return removed, 0, err
			}),
		edit("prune", "Forget files that no longer exist", "pruned", engine.Prune))
	return cmd
}

func localDevCmd() *cobra.Command {
	return verb("local-dev", "Set up without a control plane: preview works, nothing can be sent", func(cmd *cobra.Command) error {
		paths, unit, err := app.LocalDev()
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "identity %s\nstate    %s\nconfig   %s\n", unit.InstallID, paths.StateDir, paths.User)
		return nil
	})
}
