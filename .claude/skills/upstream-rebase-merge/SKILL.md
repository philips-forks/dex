---
name: upstream-rebase-merge
description: Use when syncing this dex fork with upstream dexidp/dex — rebasing the fork's long-lived feature branches onto upstream/master, and/or resetting master to upstream and re-merging the feature branches, tagging, and pushing.
---

# Upstream rebase & merge (philips-forks/dex)

## Overview

This fork carries a fixed set of long-lived feature branches on top of
`dexidp/dex`. Periodically upstream moves far enough (often including large
internal refactors) that these branches need to be rebased individually, and
`master` needs to be re-based on the new upstream tip with the feature
branches merged back in. This skill is the repeatable procedure for both
halves of that sync, plus the release tag that follows.

**Tracked feature branches** (fork-owned; edit this list if it changes):
- `feature/dcr` — OAuth2 Dynamic Client Registration (RFC 7591)
- `feature/extend-payload` — `connector.PayloadExtender` hook for ID tokens
- `feature/dynamic-scopes` — `AllowedScopePrefixes` config for non-standard scopes
- `hsdp-connector` — the `connector/hsdp` connector (2 commits: base + PKCE)

**Remotes:**
- `origin` / `philips-forks` → `https://github.com/philips-forks/dex.git` (this fork, push target)
- `upstream` → `https://github.com/dexidp/dex.git` (source of truth)

## Part 1 — Rebase each feature branch onto upstream/master

Run once per branch, in any order (they're independent until Part 2 merges them).

```bash
git fetch upstream
git checkout <branch>
git rebase upstream/master
```

### Why conflicts happen here, and the general fix

Upstream dex periodically does large internal refactors — e.g. splitting the
old monolithic `server/handlers.go` / `server/oauth2.go` / `server/server.go`
into per-domain packages (`server/authflow`, `server/grants`,
`server/discovery`, `server/tokens`, `server/session`, ...). A fork branch
written against the old layout will conflict with `modify/delete` on files
upstream deleted, and with `diff3`-style empty-HEAD-side hunks in files
upstream heavily restructured (like `server/server.go`, `server/config.go`).

The fix is **never** to blindly take "ours" or "theirs" — it's to:

1. **Diff the feature commit against its own parent** (`git show <sha>^ <sha> -- <file>`)
   to see exactly what the feature *added*, independent of the conflict noise.
2. **Find where that functionality now lives** upstream. Concretely:
   - Discovery-document fields (`server/handlers.go`'s `discovery` struct) →
     `server/discovery/discovery.go`'s `Handler`/`Document`.
   - Token minting (`s.newAccessToken`/`s.newIDToken`) → `server/tokens/issuer.go`'s
     `Issuer.SignAccessToken`/`SignIDToken`, driven by a `tokens.Authorization` struct.
   - Scope validation / "unrecognized scope" checks → `server/authflow/request.go`
     (browser flow) **and** `server/grants/grants.go`'s `validateScopes` (token
     endpoint grants) — a feature that touches scopes usually needs both.
   - Route mounting (`handleFunc("/foo", ...)` in the old `newServer`) →
     `Server.mount()` in `server/server.go`, or a new domain package's `Mount(router.Mux)`.
   - The `Config`/`Server` struct fields the old code added → add the same field
     to the *current* `Config` (now in `server/config.go`) and to whichever
     domain `Handler` struct actually reads it (not necessarily `Server` itself —
     the refactor pushed most per-request state off `Server` and onto the
     domain handlers built in `mount()`).
   - Connector registration (`ConnectorsConfig` map) → `server/connector.go`.
3. **Port the feature's logic into the new location**, matching the new
   architecture's style (dependency-injected handler structs, not methods on
   a fat `Server`).
4. **Delete the leftover `deleted-by-us` files** git left in the tree
   (`git rm -f server/handlers.go server/oauth2.go ...` etc.) — upstream
   already deleted them; the working-tree copy is just the unmerged content
   for you to have ported in step 3.
5. **Re-home tests.** Old test files for deleted source files (e.g.
   `server/oauth2_test.go`, `server/logout_test.go`) are usually also
   `both modified` conflicts against a *renamed* file (git detects the rename
   even mid-conflict — look for `HEAD:server/newpkg/foo_test.go` vs
   `parent of <sha>:server/foo_test.go` in the conflict marker). If the old
   test's target API no longer exists, drop the dead hunk and write a fresh,
   small test against the new API in the same spirit (don't skip test
   coverage for the ported feature).
6. **go.mod/go.sum conflicts** (new connector deps): `git checkout --ours
   go.mod go.sum` (take the clean upstream file), then `go get
   <newly-needed-module>@<version>` for each direct import the feature added,
   then `go mod tidy`.

After resolving each file: `git add <file>`, and once `git status` shows "all
conflicts fixed", verify before continuing:

```bash
go build ./...
gofmt -l . | grep -v vendor   # should be empty
go test ./...                 # should be all "ok"
git add -A -- ':!docs/superpowers'   # or whatever's genuinely yours to stage
git rebase --continue
```

Repeat `go build`/`go test`/`gofmt -l` after **every** rebased commit, not
just at the end — catching a break immediately is much cheaper than at the
end of a multi-commit branch.

### Push the rebased branch

Rebasing rewrites history, so it's a force push. Use `--force-with-lease`,
never bare `--force`:

```bash
git push origin <branch> --force-with-lease
```

## Part 2 — Reset master onto upstream and re-merge the feature branches

`master` on this fork accumulates its own merge commits over time and can
drift from a clean "upstream + our features" shape (e.g. picking up unrelated
one-off branches merged for other reasons). Before resetting it, **check what
you'd be discarding and confirm with the user** — this is genuinely
destructive to anything on `master` that isn't upstream and isn't one of the
tracked feature branches:

```bash
git fetch upstream
git log --oneline upstream/master..master   # everything about to be dropped
```

If that list contains more than the (old, pre-rebase) merges of the tracked
feature branches, stop and ask before proceeding — don't assume it's safe to
drop.

### Backup first

Always create a local recovery point before `reset --hard`:

```bash
git branch master-backup-pre-upstream-reset-<date> master
git tag backup/master-pre-upstream-reset-<date> master
```

### Reset and re-merge

```bash
git checkout master
git reset --hard upstream/master

for b in feature/dcr feature/extend-payload feature/dynamic-scopes hsdp-connector; do
  git merge --no-ff "$b" -m "Merge branch '$b'"
  # resolve any conflicts (same principles as Part 1 — these branches were
  # each rebased independently onto the same upstream tip, so conflicts here
  # are usually just two features editing the same new field/struct, e.g.
  # both feature/dcr and feature/dynamic-scopes adding a field to the same
  # cmd/dex/config.go struct — combine both additions, don't drop either)
  go build ./... && go test ./...
done
```

Merge order matters only if branches conflict with each other; in practice
`feature/dcr` and `feature/extend-payload` tend to be conflict-free, while
`feature/dynamic-scopes` and `hsdp-connector` are more likely to collide with
each other or with the config files the earlier merges touched — merge those
last so any conflict is against already-integrated state, not a moving
target.

After every merge: rebuild, retest, `gofmt -l .`. Fix anything before
merging the next branch — don't let breakage compound across merges.

### Tag

This fork uses `v<upstream-base-version>-dip.<N>` (e.g. `v2.45.1-dip.9`).
Find the next number:

```bash
git tag -l "v*-dip.*" | sed 's/.*dip\.//' | sort -n | tail -1
```

Increment it, keeping the same `v<version>` prefix as the existing tags
(check `git tag --sort=-creatordate | head` if the upstream base version
itself has moved), and tag the merge tip:

```bash
git tag -a v2.45.1-dip.<N+1> -m "v2.45.1-dip.<N+1>: rebase onto upstream <upstream-sha> and merge <branches...>"
```

### Push

`master` was reset, so this is also a forced update:

```bash
git push origin master --force-with-lease
git push origin v2.45.1-dip.<N+1>
```

## Safety checklist (every run)

- [ ] Fetched `upstream` fresh before starting.
- [ ] Backup branch/tag created before any `reset --hard` on `master`.
- [ ] Confirmed with the user before discarding any `master` commit that
      isn't upstream and isn't one of the tracked feature branches.
- [ ] `go build ./...`, `gofmt -l .`, `go test ./...` all clean after every
      rebased commit and every merge — not just once at the very end.
- [ ] Force pushes use `--force-with-lease`, never bare `--force`.
- [ ] Tag follows the existing `v<version>-dip.<N>` convention (increment,
      don't reuse or guess a version bump).
