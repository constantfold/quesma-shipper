# Homebrew distribution

`scripts/homebrew-cask.py VERSION ARTIFACT_DIRECTORY` renders the cask from this template and the
signed macOS binaries. The release job runs it only after TUF publication succeeds and attaches
`quesma-shipper.rb` to the GitHub release. The download URLs are immutable TUF target paths whose
SHA-256 Homebrew checks; Homebrew itself does not verify TUF metadata.

The cask installs the raw signed and notarized binary in its Caskroom, links it on `PATH`, and runs
`postinstall` without sudo, which registers the usual per-user LaunchAgent. There is one supervisor
per machine user, so switching from `.pkg` requires uninstalling it first, keeping state.

- **Updates.** The cask declares `auto_updates true`: the TUF self-updater replaces the binary in
  place and re-executes it, keeping the Brew symlink and launchd executable path. The Caskroom
  directory keeps the initially installed version name; `quesma-shipper --version` reports the
  running one. `brew upgrade` skips auto-updating casks unless run with `--cask --greedy`; a Brew
  upgrade stops the old service and registers the new version.
- **Removal.** `brew uninstall` stops the service and preserves local state; `--zap` first runs
  `quesma-shipper uninstall --purge --yes`, using the shipper's configured state directory.
  `quesma-shipper uninstall [--purge] [--yes]` removes the service but never invokes Brew or removes
  its payload.
- **Detection** follows symlinks and supports nonstandard prefixes, but expects Homebrew's normal
  `Caskroom/quesma-shipper/VERSION/quesma-shipper` layout.

## First release

1. Push the `homebrew-tap` updater workflow to its `main`, enable Actions, and let its
   `GITHUB_TOKEN` write contents on `main`.
2. Merge and publish the shipper release containing the lifecycle changes and cask asset.
3. Run the tap's **Update Quesma Shipper** workflow, or wait for its hourly check; it commits the
   release cask to `Casks/quesma-shipper.rb`.
4. Validate the public install command on a clean Mac before advertising it in onboarding.

Do not publish a cask pointing at an older shipper: those binaries reject the Caskroom path and
lack the Brew uninstall protection. No new signing credentials or cross-repository token is needed.

## Validation

The Darwin tests cover service ownership and replace a Caskroom binary through the real raw updater
behind a symlink, then check that the command link and service entry still address it.
`scripts/test-homebrew.sh` installs, upgrades, and removes a local cask on a disposable macOS CI
runner and checks launchd and state preservation. Only that temporary test cask gets a preflight
step removing quarantine from the unsigned CI binary; production casks keep Gatekeeper enabled.
