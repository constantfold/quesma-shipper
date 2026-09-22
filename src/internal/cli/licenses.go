package cli

import (
	"github.com/spf13/cobra"

	"github.com/QuesmaOrg/quesma-shipper/internal/legal"
)

func licensesCmd() *cobra.Command {
	return verb("licenses", "Print the license and the third-party notices",
		func(cmd *cobra.Command) error { return legal.Write(cmd.OutOrStdout()) })
}
