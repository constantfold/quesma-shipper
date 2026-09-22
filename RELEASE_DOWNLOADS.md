# Release downloads

This document describes the public release repository at `updates.quesma.dev` and its friendly
download endpoints. It is both an operator guide and a statement of the trust boundary for people
downloading Quesma Shipper. Both are live and are the links the installation instructions use.

## Public release repository

Release artifacts and [The Update Framework (TUF)](https://theupdateframework.io/) metadata are
stored in a public Cloudflare R2 bucket exposed through `https://updates.quesma.dev`. There is no
directory listing, so a `404` at the origin or at `/targets/` is expected. The stable entry points
are `metadata/1.root.json`, the initial offline-signed root of trust, and `metadata/timestamp.json`.

The timestamp identifies the versioned snapshot, the snapshot identifies the versioned targets
metadata, and the targets metadata contains the length and SHA-256 hash of each released file.
With consistent snapshots enabled, their URLs are:

```text
https://updates.quesma.dev/metadata/<version>.snapshot.json
https://updates.quesma.dev/metadata/<version>.targets.json
https://updates.quesma.dev/targets/<sha256>.<target-name>
```

`release.json` is itself a TUF target. It records the release version and maps platform
identifiers such as `linux/amd64` to target names; consumers should use it instead of assuming a
binary's logical name never changes. Hash-addressed target URLs are immutable but not stable
aliases: a new artifact has a new URL. They suit the updater and diagnostics, not a permanent link.

## Friendly download URLs

```text
https://updates.quesma.dev/download/quesma-shipper-macos-universal.pkg
https://updates.quesma.dev/download/quesma-shipper-linux-amd64
https://updates.quesma.dev/download/quesma-shipper-linux-arm64
https://updates.quesma.dev/download/quesma-shipper-windows-amd64.exe
https://updates.quesma.dev/download/quesma-shipper-windows-arm64.exe
https://updates.quesma.dev/download/QuesmaShipperSetup-amd64.exe
https://updates.quesma.dev/download/QuesmaShipperSetup-arm64.exe
```

Each endpoint resolves `timestamp.json`, the referenced snapshot and targets metadata, and
`release.json`, then returns a `302` to the current hash-addressed target. A `301` could leave
browsers and caches pointing at an older release. The Worker never copies, renames, overwrites,
or deletes a TUF object, and an ordinary release needs no Worker deployment.

The release publisher sets `Content-Disposition` on every R2 target to its unhashed TUF target
name, so browsers save, for example, `quesma-shipper-macos-universal.pkg`. Setting the header on the
Worker's redirect would not be enough: the browser takes the filename from the final R2 response.

## Trust boundary

The installed updater verifies TUF signatures, expiry, rollback protection, target length, and
target hash against the root embedded in the binary. That is the authenticated update path.

The Worker parses public TUF metadata for discovery but does **not** verify its signatures, and a
browser following its redirect is not a TUF client. Manual downloads therefore trust HTTPS, the
Cloudflare configuration, and any platform code signing. The macOS package is signed and
notarized. The Linux and Windows release jobs do not currently apply an operating-system code
signature; their binaries become authenticated when a TUF client verifies them. Do not describe a
manual browser download as "TUF verified". If manual downloads need that guarantee, provide a small
installer that embeds the trusted root and performs the complete TUF client workflow.

The Worker must not receive the TUF signing key, R2 API credentials, or CI publication
credentials. It needs read access only to URLs that are already public.

## Worker implementation

```ts
const downloads: Record<string, string> = {
  "/download/quesma-shipper-macos-universal.pkg": "darwin/pkg",
  "/download/quesma-shipper-linux-amd64": "linux/amd64",
  "/download/quesma-shipper-linux-arm64": "linux/arm64",
  "/download/quesma-shipper-windows-amd64.exe": "windows/amd64",
  "/download/quesma-shipper-windows-arm64.exe": "windows/arm64",
  "/download/QuesmaShipperSetup-amd64.exe": "windows/amd64/setup",
  "/download/QuesmaShipperSetup-arm64.exe": "windows/arm64/setup",
};

type Metadata = {
  signed?: {
    meta?: Record<string, { version?: unknown }>;
    targets?: Record<string, { hashes?: { sha256?: unknown } }>;
  };
};

// release.json is plain JSON, not signed metadata; the separate type keeps the two apart.
type Release = { targets?: Record<string, unknown> };

async function readJSON<T>(origin: string, path: string): Promise<T> {
  const response = await fetch(`${origin}/${path}`);
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json() as Promise<T>;
}

function version(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`invalid ${label}`);
  }
  return value;
}

function hash(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`invalid ${label}`);
  }
  return value;
}

export default {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
    }
    const url = new URL(request.url);
    const platform = downloads[url.pathname];
    if (!platform) return new Response("Unknown download", { status: 404 });

    try {
      const timestamp = await readJSON<Metadata>(url.origin, "metadata/timestamp.json");
      const snapshotVersion = version(timestamp.signed?.meta?.["snapshot.json"]?.version, "snapshot version");
      const snapshot = await readJSON<Metadata>(url.origin, `metadata/${snapshotVersion}.snapshot.json`);
      const targetsVersion = version(snapshot.signed?.meta?.["targets.json"]?.version, "targets version");
      const targets = await readJSON<Metadata>(url.origin, `metadata/${targetsVersion}.targets.json`);
      const releaseHash = hash(targets.signed?.targets?.["release.json"]?.hashes?.sha256, "release manifest hash");
      const release = await readJSON<Release>(url.origin, `targets/${releaseHash}.release.json`);

      const targetName = release.targets?.[platform];
      if (typeof targetName !== "string" || !/^[A-Za-z0-9._-]+$/.test(targetName)) {
        throw new Error(`invalid target for ${platform}`);
      }
      const targetHash = hash(targets.signed?.targets?.[targetName]?.hashes?.sha256, "target hash");
      return new Response(null, {
        status: 302,
        headers: { Location: `${url.origin}/targets/${targetHash}.${targetName}`, "Cache-Control": "no-store" },
      });
    } catch (error) {
      console.error(error);
      return new Response("Release temporarily unavailable", { status: 503 });
    }
  },
};
```

The Worker reads the public origin rather than using an R2 binding, so it holds no credentials and
cannot mutate the bucket. Its route matches only `/download/*`, so `/metadata/*` and `/targets/*`
continue to the R2 origin.

## Cloudflare setup

The `quesma.dev` zone and the R2 custom domain must be in an account where Workers can add a
route, and the `updates.quesma.dev` DNS record must stay proxied through Cloudflare.

1. In **Workers & Pages**, create a Worker named `quesma-release-downloads` from the code above.
   It needs no variables, secrets, or R2 binding.
2. Under **Settings > Domains & Routes**, add a route (not a Worker Custom Domain) for
   `updates.quesma.dev/download/*` in the `quesma.dev` zone, configured to fail closed so a failure
   is an error rather than an R2 object lookup.
3. Leave the R2 custom domain in place. It keeps serving every unmatched path.

The equivalent Wrangler configuration:

```toml
name = "quesma-release-downloads"
main = "src/index.ts"
compatibility_date = "2026-09-09"
compatibility_flags = ["global_fetch_strictly_public"]

routes = [
  { pattern = "updates.quesma.dev/download/*", zone_name = "quesma.dev" }
]
```

Do not add an `r2_buckets` binding or commit account IDs, API tokens, bucket names, or
credentials. The compatibility flag lets the Worker fetch public URLs in its own zone and grants
no access to private resources; without it, a same-zone subrequest can fail with error `1042`.
See Cloudflare's [Worker routes](https://developers.cloudflare.com/workers/configuration/routing/routes/)
and [R2 custom domains](https://developers.cloudflare.com/r2/buckets/public-buckets/).

## Deployment checks

Before deploying the route, check the metadata chain:

```sh
curl -fsS https://updates.quesma.dev/metadata/1.root.json >/dev/null
curl -fsS https://updates.quesma.dev/metadata/timestamp.json >/dev/null
```

After deployment, every friendly endpoint must answer `302` with a `Location` under
`https://updates.quesma.dev/targets/`, and the target must return `200` with an unhashed filename
in `Content-Disposition`:

```sh
curl -fsSI https://updates.quesma.dev/download/quesma-shipper-linux-amd64
curl -fsSIL https://updates.quesma.dev/download/quesma-shipper-linux-amd64
```

Also test both Linux architectures, both portable and setup downloads on Windows, and the macOS
package on a supported Mac.

The release workflow publishes targets first, versioned metadata second, and `timestamp.json`
last. Preserve that order: the Worker reads the timestamp first, so it sees either the complete
previous release or the complete new one.

## Operations and rollback

- Monitor Worker `5xx` responses and the expiry of TUF metadata.
- Keep redirects uncached; a short cache lifetime such as 60 seconds can be considered later.
- Worker requests and R2 reads count against their Cloudflare allowances; see the
  [Workers](https://developers.cloudflare.com/workers/platform/pricing/) and
  [R2](https://developers.cloudflare.com/r2/pricing/) pricing pages rather than copying prices here.
- To roll back, remove or disable only the `updates.quesma.dev/download/*` route. Never remove the
  R2 custom domain or change `/metadata/*` or `/targets/*`; installed clients depend on them.
