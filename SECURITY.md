# Security Policy

This repository publishes subscription lists built from third-party VPN
configurations. This document states what the project does to a reader's trust,
where its trust boundary runs, which weakenings are deliberate, and how to report
a problem. It describes the code as it stands; it is not a promise about a future
version, and it claims nothing the code does not do.

## What the published artifacts are

The pipeline fetches configuration files from hundreds of sources it does not
control, parses them, filters and sorts them, and commits the result into
`githubmirror/` — which is what consumers subscribe to.

There is no signature on the output and no authentication of the upstreams. The
list is a **filtered** collection of third-party configurations, not a vetted
one. Anyone who can influence a source can influence what appears in the
published list, and a configuration in that list decides where a consumer's
traffic goes. Treat these files as untrusted input: do not route traffic you care
about through a configuration taken from a public list of this kind without
deciding for yourself whether you trust the endpoint.

What the pipeline *does* do is narrower than "verification": it checks that a
configuration parses, drops the ones carrying insecure protocol settings (see
[the security-system page](docs/development/security-system.md)), tests whether
the endpoint responds, and sorts by measured latency. None of that is a claim
about the operator behind an endpoint.

## The trust boundary

Curated input — everything else is untrusted:

* `source/config/URLS.txt` — the source list a maintainer edits, including its
  Telegram, YAML and bypass sections;
* `source/config/servers.txt` — individual configurations added by hand;
* the hardcoded upstreams in the fetcher modules: `sstap.org`, the daily
  date-rotating repositories in `config/settings.py`, and the two upstream lists
  read by `fetchers/upstream_aggregator.py`;
* the repository itself, once a maintainer commits to it.

Everything downstream of those is third-party content: the bodies of the fetched
files, the configurations inside them, and anything they contain. The pipeline
reads that content as text and parses it as configuration or as JSON/YAML with
`safe_load`; it does not execute it, and no fetched body is treated as code.

One place does read URLs out of fetched content, and it is bounded on purpose:
`fetchers/upstream_aggregator.py` extracts URLs from two hardcoded upstream lists
and keeps only lines whose host is exactly `hh.yudou226.top`, or a
`gist.githubusercontent.com` path under `/guidongone/`. A poisoned upstream list
therefore cannot make the pipeline fetch an arbitrary destination — it can add a
path on those two hosts, and each of those fetches goes through the same guard
described below.

## Deliberate weakenings

Each of these is a known trade, recorded here so it is a decision rather than a
surprise.

### The TLS retry ladder

`fetchers/fetcher.py` retries a failed fetch in this order. The order and the
retry count are load-bearing: this pipeline runs on a network that actively
interferes with TLS, and without the middle attempts a large share of the sources
is simply unreachable.

| Attempt | What it sends | What it costs |
|---|---|---|
| 1 | the request over TLS, certificate verified | nothing |
| 2 | the same request with certificate verification **off** | a forged or intercepted certificate is accepted |
| 3 | the same request over **plaintext HTTP**, when the URL is https | anything on the path can read and rewrite it |
| — | GitHub API fallback (`api.github.com`), verified TLS, token sent only to GitHub hosts | runs first for GitHub raw/blob URLs when `GITHUB_API_FALLBACK` is on (the default); the ladder runs if it fails |

**The honest consequence:** an attacker who can break or block TLS can influence
the fetched configurations and therefore the published list. What they cannot do
is execute anything: the body is parsed as configuration text.

What is not acceptable is silence, and that is what changed. The fetcher logs
every downgrade with the host and the attempt, counts them, and prints the run's
total — attempts and distinct hosts — in the end-of-run report next to the URL
health report. An operator who would rather lose the sources than take the
downgrade sets `REFUSE_INSECURE_FETCH=1`, which skips attempts 2 and 3; the cost
is fetch yield, and that cost is the reason it is off by default.

### Raw output is not published

`PUBLISH_RAW_FILES = False` (`source/config/settings.py`) keeps the `/raw/`
subfolders out of the published tree: those are pre-verification configurations.
The CLI overrides exist (`--publish-raw-files`), and turning them on publishes
configurations that no test has run against.

### SNI/CIDR filtering is selection, not security

The SNI/CIDR filter picks configurations whose endpoint is inside a curated
whitelist, so the generated lists work against mobile network whitelists. It says
nothing about whether an endpoint is honest, well-run, or safe to use — it is a
routing-property filter. Confusing the two would be a mistake the documentation
does not intend, which is why it is stated here.

## The fetch guard

A fetch refuses a destination that is not a globally routable address — loopback,
private, link-local (including the cloud metadata endpoint `169.254.169.254`,
which matters because this pipeline runs unattended on a VPS), carrier-grade NAT,
reserved or unspecified space. An allowlist
(`FETCH_PRIVATE_ALLOWLIST`, empty by default) is the only exception, and it is an
operator decision, not a bypass.

Two honest limits:

* the check runs on the **resolved** address before the request, and the client
  resolves again when it connects, so a resolver that answers differently between
  the two can still slip through. The redirect target is checked as well, and a
  body fetched from a refused destination is discarded before the pipeline sees
  it, which narrows that window rather than closing it;
* a name that cannot be resolved is not refused. It is logged and the request
  proceeds, where the failure is reported as itself.

Neither the guard nor anything else in this project validates the *content* of a
fetched configuration beyond parsing it and checking its insecure settings.

## Supply chain

The published list changes constantly: the pipeline commits its own output
automatically (`auto: update ...` commits, on the order of tens per day on the
operating host; the GitHub workflow in this repository schedules a run every two
days, and a maintainer's own schedule may be denser). Consumers pin a
subscription **URL**, not a commit, so what they import tomorrow is not what they
imported today. Nothing in this repository signs or attests a revision of the
list.

## Credentials and tokens

* `.env` holds `MY_TOKEN` (or `GITHUB_TOKEN`) and is never committed — it is in
  `.gitignore`. `config/settings.py` reads it into the process only.
* The token is sent only to `github.com` / `raw.githubusercontent.com` requests
  (and to the API fallback), never to the arbitrary hosts in `URLS.txt`.
* An attacker holding a token with `repo` scope could write to the artifacts this
  repository publishes — including by pushing a commit that adds a
  configuration. The token is the highest-value credential in the project, and it
  is not the only path to the artifacts: write access to the repository, or to
  any upstream in `URLS.txt`, has a comparable effect on what a consumer receives.
* The GitHub workflow uses the repository's own `GITHUB_TOKEN` with
  `permissions: contents: write`, scoped to that job.

## Out of scope

* The configurations themselves. They are third-party, unverified by design, and
  this project neither endorses nor audits the operators behind them.
* The security properties of the protocols listed (VMess, VLESS, Trojan,
  Shadowsocks, …) and of the clients that consume the list.
* Anything under `githubmirror/` — it is generated output. A problem there is
  reported here only when it was produced by a defect in this code.
* The networks this project is used to circumvent, and the legal position of a
  consumer in their own jurisdiction.

## Reporting a vulnerability

No personal contact details are needed, and none are published here on purpose.

* For an ordinary defect — a parsing crash, a source that should be dropped, a
  behavior that does not match this document — open a GitHub issue describing it.
* If the report is itself sensitive (an exploitable weakness you would rather not
  publish while it is open), use GitHub's private vulnerability reporting on the
  repository's Security tab, if it is available. If it is not, open an issue that
  says only that you have a sensitive report and asks for a private channel — do
  not put the details in the issue.

Please include what you observed, the source or configuration that reproduces it,
and which part of this document it contradicts, if any.
