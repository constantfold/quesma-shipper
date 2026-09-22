package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/cli"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// reportPanic prints the stack to stderr only, since it can carry payload strings, and persists the fact.
func reportPanic(errOut io.Writer, args []string, r any) {
	fmt.Fprintf(errOut, "panic: %v\n\n%s", r, debug.Stack())
	app.RecordPanic(verbOf(args), r)
}

// verbOf is the first non-flag argument, so `quesma-shipper -q sync` still reads as sync.
func verbOf(args []string) string {
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return app.Name
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			reportPanic(os.Stderr, os.Args, r)
			os.Exit(2)
		}
	}()
	if err := platform.ApplyMaxInFlightBytesFromEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", app.Name, err)
		os.Exit(1)
	}
	root := cli.Root(app.NewBuild(), os.Stdout, os.Stderr)
	err := root.ExecuteContext(context.Background())
	if code, show := cli.ExitCode(err); code != 0 {
		if show {
			fmt.Fprintln(os.Stderr, cli.ErrorLine(err, os.Stderr))
		}
		if code == 2 {
			fmt.Fprintln(os.Stderr, cli.HelpPointer(os.Stderr))
		}
		os.Exit(code)
	}
}
