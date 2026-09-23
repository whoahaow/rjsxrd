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

### The fetch retry policy

`fetchers/fetcher.py` retries a failed fetch as the same verified request: every
attempt sends the request over TLS with the certificate checked, one second
apart. Nothing leaves this process unverified or in the clear unless the operator
asks for that.

| Attempt | What it sends | What it costs |
|---|---|---|
| 1-3 | the same request over TLS, certificate verified | a source reachable only without verification is lost |
| — | GitHub API fallback (`api.github.com`), verified TLS, token sent only to GitHub hosts | runs first for GitHub raw/blob URLs when `GITHUB_API_FALLBACK` is on (the default); the retries run if it fails |

**The honest consequence:** a source whose TLS the network breaks or intercepts
is not fetched. It fails like any unreachable source, ages out of `URLS.txt`
after three runs and disappears. This pipeline runs on a network that actively
interferes with TLS, so that is a real loss of yield, taken on purpose: the
alternative lets anyone who can break TLS on the path decide which
configurations get fetched and therefore published. They cannot execute anything
— the body is parsed as configuration text — but they can put their own server
into the list, and a subscription list is trusted by the clients that import it.

`ALLOW_TLS_DOWNGRADE=1` restores the ladder this replaced, where attempt 2
skipped certificate verification and attempt 3 re-sent the request over plaintext
HTTP. It is a reach setting, and what it buys is exactly what it risks.

Silence is still the one outcome that is not acceptable. Every downgrade that
does happen is logged with its host and the attempt number, counted, and printed
in the end-of-run report next to the URL health report, which also states which
of the two policies ran.

A failure is evidence about its source under either policy, so it ages the URL.
The outcomes that say nothing about a source are the ones where no request left
the process — a destination refused before the request or after a redirect, and a
call that asked for no attempt — and those are named in the run's report instead
of counted against the source (`utils/fetch_outcomes.py`).

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
operator decision, not a bypass: an IP literal, a CIDR, or `host` / `host:port`, where
a v6 host is written the way a URL writes it (`[::1]`, `[::1]:1080`) and a
port-qualified entry covers the port the request will use and no other. An entry that
covers a whole address family (`0.0.0.0/0`, `::/0`) is refused when the setting is read
— it does not widen the guard, it switches it off.

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

### What the guard covers, and what it does not

The guard is on the fetch path: `fetchers/fetcher.py:fetch_data()`, which is where
every URL this pipeline fetches from its own input goes — the `URLS.txt` sources, the
daily-repo fetchers, and the aggregator's output.
`_destination_refusal(url, FETCH_PRIVATE_ALLOWLIST)` is the decision; it is made before
the session is built, and again for the address a redirect actually ended at.

It is not on every HTTP call in the tree. The surfaces the audit measured, and why each
is outside it:

| Surface | What it fetches | Why the guard is not the control |
|---|---|---|
| `scripts/purge_stale_urls.py` — `build_github_session()`, `check_rate_limit()`, `get_last_commit_date()` | the GitHub API, for the last commit date of a file behind a `github.com` / `raw.githubusercontent.com` URL | the owner, repo and path come from `URLS.txt`, but the request goes to `api.github.com`, a literal in that module. The untrusted input chooses a path on a host this module fixes, not a destination |
| `scripts/benchmark_configs.py` — `resolve_path()` | this project's own `githubmirror/bypass/bypass-all.txt` | the URL is a module-level literal on `raw.githubusercontent.com`, and the script takes no URL from its arguments or its environment. The audit recorded this one as an operator-supplied URL; the code has no such input. If that changes, the rule below applies to it |
| `utils/ip_verifier.py` — `_make_request()` and its callers | the IP-echo providers in `IP_CHECK_URLS` | the destinations are that module's own constants. Its `proxies` argument does come from outside (the operator's `--proxy` / `--proxy-chain`), but the guard judges a *destination*, not a route: a private proxy address is not a URL this guard could refuse, and refusing one would not be the control that helps |
| `utils/xray_tester.py` — `_get_session()`, called from `utils/xray_batch.py` | the ping URLs in `TEST_PING_URLS`, which are operator-supplied | the request is sent through a SOCKS listener on loopback (`socks5h://127.0.0.1:{port}`), so the URL's host is resolved by the proxy under test and not by this process. The guard's question — what does *this* process resolve the name to — does not arise, and refusing on a local answer would forbid a URL the proxy can reach |

Three more clients in the tree request fixed hosts and are outside for the same reason:
the Xray release download (`utils/download_xray.py`, `api.github.com` plus the
`github.com/XTLS/Xray-core` release URLs), the Telegram notifier's POST
(`utils/telegram_notifier.py`, `api.telegram.org`), and the proxy probe
(`utils/telegram_proxy_verifier.py`, its own `TEST_URL` through the proxy it is
checking).

What none of those, and not this guard either, judges is a *route*: a proxy address, a
SOCKS hop or a bind address that came from a fetched body is a different question from
the destination a URL names, and this section answers the second.

**The rule for a new fetch site.** If the URL it fetches can be influenced by something
this project does not control — a fetched body, `URLS.txt`, the operator's arguments or
environment — it goes through `_destination_refusal(url, FETCH_PRIVATE_ALLOWLIST)`
before the request is made, and a response that arrived from a different host goes
through it again. That function is the seam: it is importable, it needs no session and
no configuration of its own, and for a handful of call sites a wrapper around it would
be more to maintain than the call. A site that stays outside is added to the table
above with its reason — which is what keeps this section a statement about this code
rather than a claim about all of it.

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
* The token is sent only to an explicit set of GitHub hosts — `github.com`,
  `raw.githubusercontent.com`, and `api.github.com` (the host the API fallback requests,
  built from one of the other two) — matched against the **hostname** of the request
  (`GITHUB_TOKEN_HOSTS` in `source/fetchers/fetcher.py`), never to the arbitrary hosts in
  `URLS.txt`. A GitHub name that appears only in a URL's path or query string receives
  nothing.
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
