# Contributing

All participation is subject to the [code of conduct](CODE_OF_CONDUCT.md).

## Setup

Install Go 1.27 or newer (`make doctor` lists the optional tools), then run `make build` and
`make test`. The Go module root is `src/`: run `go` commands there, or `make` from the root.

## Before you open a pull request

```sh
make check
```

This is the commit gate CI runs: gofmt, go vet with a Windows type-check, VERSION validation,
dead-code detection, the dependency license check, and the unit suite under the race detector.
`make test` is the faster local loop.

Open the pull request as a draft; a maintainer marks it ready for review. Put small fixes on the
same branch and a larger follow-up in a stacked pull request. In the description, state what
changed and why, give a concrete before-and-after example, and include a binary-size or
performance diff when the change can affect either.

## Design rules

[CONSTITUTION.md](CONSTITUTION.md) is the design authority: a change that conflicts with an
article is not merged, and a change to the constitution is its own pull request arguing the
trade-off. [ARCHITECTURE.md](ARCHITECTURE.md) states which package can import which; say so in the
description if a change needs a new edge.

Reviewers check these invariants on every change:

- Scrub fails closed. A scrub error means the file is not uploaded.
- No configuration layer can remove scrub or encrypt.
- No cloud SDK is imported. Upload is `net/http` only.
- Only the packages that own a durable artifact write to disk directly. All other writes go
  through `safeio`. The shipper never writes inside an agent's store.

## Golden tests and compatibility

Golden tests pin output byte for byte: `src/e2e/golden_test.go`, the conformance vectors under
`src/conformance/`, and the wire fixtures the contract tests import from the
[shipper-protocol](https://github.com/QuesmaOrg/shipper-protocol) module. A golden diff is a claim
that the output must change: read it, explain it in the pull request, and do not run with
`-update` until a maintainer agrees. Regenerating conformance vectors recalculates their expected
outputs without replacing the inputs and case descriptions in the vector JSON files.

File formats, the wire protocol, configuration keys, and the object-key grammar are compatibility
surfaces. A change to one needs a test showing old inputs still work, and a note in the pull
request. A protocol change is made and released in the shipper-protocol repository first; the
shipper then bumps the dependency.

Do not widen a performance budget or make a test less strict. If you must, say so in the pull
request.

## Code style

- Comment the intent and the non-obvious corner cases. Do not describe what the code does.
- Use about three lines of top-level comment per file. Use one line elsewhere.
- Keep dependencies few. Argue each new one in the pull request. `make check` rejects licenses
  outside Apache-2.0, MIT, BSD, ISC, and Unlicense.
- After a large change, simplify before you ask for review.

## Test data

Do not commit real trajectories, prompts, transcripts, agent databases, logs, encrypted bundles,
credentials, or private project data. Use small synthetic fixtures with `example.com` addresses,
placeholder usernames, and invented project names; `.gitignore` blocks the common file types as a
last line of defence. If you need real data to reproduce a bug, minimise and redact it locally,
then share it through a private channel as described in [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the project's Apache License 2.0. By submitting a pull request,
you confirm that you have the right to license your contribution under those terms.
