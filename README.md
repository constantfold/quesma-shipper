# Quesma Shipper

[![version](https://img.shields.io/badge/version-0.0.3-blue)](#install)

Quesma Shipper collects the session files and related artifacts that AI coding agents write on a
developer machine ([what is collected](#what-is-collected)). It removes secrets and personal data
from each file, encrypts the file with [age](https://age-encryption.org/), and uploads the
ciphertext to your organisation's object storage. It runs in the background as one static Go
binary, and a central control plane manages every install.

Supported agents: Claude Code, Codex, Cursor.

Supported platforms: macOS 13 or newer (app bundle, launchd service), Linux (systemd user
service), Windows 10 1809 or newer (per-user installer, scheduled task).

## Install

Every installer below is per-user and needs no administrator rights. Released builds, Homebrew
included, keep themselves current from the signed [TUF](https://theupdateframework.io/) update
channel; run `quesma-shipper update` to update immediately. [RELEASE_DOWNLOADS.md](RELEASE_DOWNLOADS.md)
describes the endpoints and their trust boundary.

| Platform | Download |
|---|---|
| macOS 13+ | [quesma-shipper-macos-universal.pkg](https://updates.quesma.dev/download/quesma-shipper-macos-universal.pkg), or with Homebrew `brew install --cask quesmaorg/tap/quesma-shipper` |
| Windows 10 1809+ | [QuesmaShipperSetup-amd64.exe](https://updates.quesma.dev/download/QuesmaShipperSetup-amd64.exe) for x64, [QuesmaShipperSetup-arm64.exe](https://updates.quesma.dev/download/QuesmaShipperSetup-arm64.exe) for Arm |
| Linux | `curl -fsSLO https://raw.githubusercontent.com/QuesmaOrg/quesma-shipper/main/src/packaging/linux/install.sh && sh install.sh` |

**macOS.** The signed `.pkg` installs `Quesma Shipper.app` for the current user and registers a
launchd agent. The Homebrew cask puts the command on your Homebrew `PATH` and starts the same
per-user service, on Apple Silicon and Intel. Remove the cask with
`brew uninstall --cask quesmaorg/tap/quesma-shipper`, which keeps enrollment and upload history;
add `--zap` to delete local state too, using the shipper's configured state directory. Before
switching between Homebrew and the `.pkg`, uninstall the previous installation without purging
local state.

**Linux.** The script downloads a hash-pinned bootstrap binary and installs a systemd user
service. Run it again to upgrade; existing enrollment is kept. Use `--no-service` to skip the
service. Plain binaries are also available for
[AMD64](https://updates.quesma.dev/download/quesma-shipper-linux-amd64) and
[ARM64](https://updates.quesma.dev/download/quesma-shipper-linux-arm64).

**Windows.** Run the setup as your normal user. It installs the command under `%LOCALAPPDATA%`,
adds it to your user `PATH`, and registers a scheduled task that starts immediately and at login.
Re-running setup repairs that integration without changing enrollment. Release signing is
temporarily disabled while the publisher identity is validated, so SmartScreen may warn about the
download and application-control policies that require a trusted publisher may block it. The raw
`quesma-shipper-windows-<arch>.exe` files are the payloads the self-updater installs; run
portably, they have no scheduled task or uninstaller.

## Status

The project is pre-1.0. The wire protocol, the configuration format, and the object naming are
versioned and tested, but can still change between minor releases.

<!-- TODO(control-plane-oss): link the control-plane repository here.  https://github.com/QuesmaOrg/quesma-shipper/issues/1 -->
Uploading needs a control plane, which is not part of this repository and is not published yet.
Without one the shipper runs in local development mode: collection, scrubbing, and preview work;
upload is disabled.

`trajectory-shipper` remains the wire identifier and the on-disk configuration and state namespace.

## How it works

```
agent session files ──► discover ──► detect change ──► read ──► scrub ──► encrypt ──► upload ──► commit
                        (catalog)    (size, mtime,              (rule     (age, to     (presigned  (local
                                      content hash)              packs)    org keys)    PUT)        record)
```

- **Sources.** A compiled catalog describes where each agent stores sessions and how to read them.
  This includes live SQLite databases. The shipper never writes inside an agent's store.
- **Scrub.** Every file passes through redaction rule packs first. Three provider-key packs
  (`gitleaks-core`, `quesma-extra`, `cloud-keys`), an entropy backstop (`generic-entropy`), and a
  PII pack (`pii-core`) are compiled in. The control plane can add packs. It cannot remove them.
  A scrub error means the file is not uploaded.
- **Encrypt.** The scrubbed file is sealed with age to the recipients that the control plane
  supplies. The client can be configured to hold no key that decrypts what it ships.
- **Upload.** The control plane authorises each upload with a presigned URL. Ciphertext goes from
  the client directly to the sink. The control plane never receives trajectory bytes. No cloud SDK
  is linked. The upload path is `net/http` only.
- **Commit.** A local record of shipped files is updated after the sink confirms the write. That
  record is the authority for resume.
- **Update.** Release builds replace themselves when the TUF repository has a newer signed
  release. Development builds do not self-update.

The design rules are in [CONSTITUTION.md](CONSTITUTION.md), the code layout in
[ARCHITECTURE.md](ARCHITECTURE.md). The wire contract is the public
[shipper-protocol](https://github.com/QuesmaOrg/shipper-protocol) module, whose schemas and fixtures
this repository imports; protocol changes are reviewed and released there.

## What is collected

The shipper collects more than chat transcripts. Per agent, from the agent's own directories:

| Agent | Trajectories | Context artifacts |
|---|---|---|
| Claude Code | Session and subagent transcripts, spilled tool results | Per-project memory files, plans, todos, file-history checkpoint metadata, the user-level `CLAUDE.md`, `settings.json` |
| Codex | Sessions, archived and compressed sessions, the session index | None |
| Cursor | Agent transcripts, enriched with conversation text, tool calls, and model names read from Cursor's database | Spilled tool output, terminal captures, agent scratchpad notes |

Two more records are produced by the shipper itself:

- **Project map.** For each project directory an agent used: the directory name, the working
  directory, and the git remote as host and path. Credentials embedded in a remote URL are removed
  before the value is written anywhere.
- **Account and usage history.** Independent Claude Code, Codex, and Cursor collectors upload
  account metadata and provider usage JSON in UTC buckets matching the collection interval (default 15 minutes). Unknown fields are preserved;
  these records skip scrubbing and ship encrypted.

All other files above pass through the scrub stage before encryption. The control plane receives no
file content. It receives the install id, hostname, platform, and agent version in each heartbeat.

Never uploaded as files: credential stores such as Claude Code's `.credentials.json` and
`~/.claude.json`, Codex's `auth.json`, and Cursor's `state.vscdb`. A compiled deny list blocks
these paths even when a configured glob would match them. Collectors and enrichers read only
the data they need from these stores:

- Account collectors read account metadata and use credentials only to authenticate provider requests.
- The Cursor enricher reads conversation records from `state.vscdb` and writes the conversation
  text, tool calls, and model names it finds into the transcript record, because Cursor's own
  transcript files lack them. The `cursorAuth/*` keys and the encryption-key fields are stripped
  by a compiled rule that no configuration layer can disable.

Everything derived this way passes through the scrub stage like any other file.

## Enroll

Enroll every new shipper with the control plane your administrator selected, on any platform:

```sh
quesma-shipper login <enrollment-token> --server https://cp.example.com
```

Without a control plane, `quesma-shipper local-dev` creates a local identity and state directory,
and `quesma-shipper preview` shows what would be collected and how it would be scrubbed.

## Usage

```
quesma-shipper                Status: is it on, what is collected, what is waiting to be sent
quesma-shipper login <token>  Join your organisation with the token from your admin
quesma-shipper tracking       What is collected, per agent and repository
quesma-shipper pause [dur]    Stop collecting for 15m, 1h, 6h, 12h, 24h, or until tomorrow 9:00
quesma-shipper resume         Start collecting again
quesma-shipper doctor         Check collecting and sending, explain anything wrong
quesma-shipper update         Install the newest release
quesma-shipper uninstall      Remove the service and program, keep local state
quesma-shipper licenses       Print the license and the third-party notices
```

Debug commands. These are not shown in `--help`:

```
quesma-shipper run [--once|--drain] [-q]   Run the scheduler loop in the foreground, log to stderr
quesma-shipper preview                      Show what would be sent, without sending or recording anything
quesma-shipper config [--with-provenance]   The effective configuration and where each value came from
quesma-shipper log                          Recent audit entries: what was decided about each file
quesma-shipper state reset|prune            Inspect and repair the local record of what was sent
quesma-shipper service uninstall|restart    Manage the background service entry
quesma-shipper local-dev                    Set up without a control plane
```

## Configuration

Configuration is resolved from four layers, in this order: compiled defaults, the source catalog,
the user file, the document served by the control plane. `quesma-shipper config --with-provenance` prints
each effective value and the layer that set it.

The served document has limited authority: a rulebook in the shipper-protocol module states, field
by field, what the control plane can change. It can add scrub rule packs but not remove them, and
it cannot turn off scrub or encryption. Contract tests here and in the control plane enforce it.

File locations. `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are honoured.

| Path | Contents |
|---|---|
| `~/.config/trajectory-shipper/config.yaml` | Optional user layer |
| `~/.local/state/trajectory-shipper/` | Identity, upload record, audit log, run logs |

Defaults: a 15-minute schedule, a maximum of 512 files per run, a 5-minute drain deadline.

Environment variables:

| Variable | Effect |
|---|---|
| `SHIPPER_AUTH_KEY` | Supplies the login token without a prompt |
| `SHIPPER_NO_SELFUPDATE` | Any value disables the self-update check |

## Security model

Trajectory files contain prompts, source code, shell output, and often credentials: treat local
state, logs, and encrypted bundles as confidential. Scrub and encrypt are mandatory in every
build, the client holds no long-lived storage credential, one install cannot overwrite another
install's objects, and updates are verified against an offline-signed TUF root embedded in the
binary. Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Build and test

You need Go 1.27 or newer. No other tool is required; `make doctor` lists the optional ones.

```sh
make build       # bin/quesma-shipper
make install     # into GOBIN, or GOPATH/bin
make test        # unit suite and local end-to-end tests
make race        # the same under the race detector
make check       # the commit gate: fmt, vet, version, dead code, licenses, race
make perf-smoke  # PR-sized performance gates, needs Docker
make perf        # full performance suite, needs Docker
make help        # every target
```

CI runs `make check` and `make perf-smoke`. Both perf targets run against a local MinIO and
Toxiproxy and are skipped without Docker. Cross-service tests that need the control plane are not
part of this repository.

Packaging a local build:

- Linux installer and service: `make build && sh src/packaging/linux/install.sh --from bin/quesma-shipper`.
- macOS package (macOS only): `make macos-pkg RELEASE_VERSION=<version>`.
- Windows binaries: `make dist RELEASE_VERSION=<version>` cross-compiles them. With Inno Setup
  installed, build the installer with `src/packaging/windows/build-setup.ps1 -ReleaseVersion <version>
  -Architecture amd64 -BinaryPath <binary> -SupervisorPath <supervisor-binary> -OutputDir bin/dist`.

## Versions and releases

`VERSION` contains the reviewed `MAJOR.MINOR.PATCH` release line; change it only to start a new
line. `make version-check` validates it. Release builds are stamped
`<VERSION>-<commit count>.<short sha>` by `scripts/release-version.sh` (`make release-version`
prints it). Development builds are not stamped, report their commit, and do not self-update.

A push to `main` that touches the shipper builds six platform binaries and the macOS package, signs
TUF metadata, and publishes to `https://updates.quesma.dev`. It then creates a
[GitHub release](https://github.com/QuesmaOrg/quesma-shipper/releases) linking the stable downloads.
A maintainer approves each publication.

Each GitHub release also carries a `quesma-shipper.rb` cask pinned to the published macOS binaries.
The [Homebrew tap](https://github.com/QuesmaOrg/homebrew-tap) imports it hourly or on a manual workflow
run. See [Homebrew packaging](src/packaging/homebrew/README.md) for the first-release rollout and checks.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Do not attach
real trajectories, agent databases, logs, or credentials to issues or pull requests.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). `quesma-shipper licenses` prints the
license and every bundled dependency's license text; the same texts ship inside the macOS app
bundle and live in `src/internal/legal/third_party/`, with a `licenses.csv` inventory covering
all three platforms. `make licenses` regenerates them; `make check` fails when they are stale or a
dependency is not permissively licensed.

Quesma, Quesma Shipper, and the Quesma logo are trademarks of Quesma Inc. The license does not
grant trademark rights. If you distribute a modified build, read [TRADEMARKS.md](TRADEMARKS.md)
before you name it.
