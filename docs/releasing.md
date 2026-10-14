# Cutting a release

Written down because the parts are spread across three places - the repository, the workflow, and the machine
that holds the signing certificate - and the failure modes are quiet ones.

## 1. Land the work, then bump the manifest

```
npm run check                 # the four invariants
node scripts/selfcheck.mjs    # 280 checks over the tool surface
```

Bump `version` in `package.json` and commit it. The tag, the tarball and the manifest have to name the same
release: the release script refuses to run when they disagree, rather than tagging one version and publishing
another.

## 2. Release from the signing machine

The signing toolchain (outside this repository, on the machine that holds the code signing certificate) has a
`release-mega.ps1` that owns this project's paths and arguments:

```
release-mega.ps1 -Version 0.3.8                 # preconditions, pack, sign, verify, archive
release-mega.ps1 -Version 0.3.8 -Tag            # ... then tag at HEAD and push
release-mega.ps1 -Version 0.3.8 -Tag -Publish   # ... then attach the signed files to the release
release-mega.ps1 -Version 0.3.8 -DryRun         # preconditions and pack only, nothing signed
```

It stops, rather than continuing, on: a dirty worktree, a manifest version that disagrees with `-Version`, a
tag that already exists, failing invariants, or a signature that does not verify. Each of those was checked by
fault injection before being trusted.

The tag is placed at **HEAD**, because the tarball was packed from HEAD. An earlier release was tagged three
commits after the commit it was built from, which makes "does this tag's tree produce this tarball" a question
nobody can answer from the outside.

## 3. What CI does with the push

| job | when | what |
|---|---|---|
| `invariant` | every push and tag | the ASCII invariant and the consistency proofread; cheap, no dependencies |
| `release` | tags matching `v*` | creates the GitHub Release, with notes built from the commits since the previous tag |
| `npm` | pushes to **main**, and only when the repository variable `NPM_PUBLISH` is `true` | publishes to the npm registry, skipping when that version already exists there |

Three consequences worth knowing:

- **A tag push never runs the npm job.** Its condition is `github.ref == 'refs/heads/main'` plus the variable,
  so tagging is not a publish button. Publishing to the registry is opt-in twice over.
- **The npm job needs credentials that are not in this repository**: either a Trusted Publisher configured for
  this repository on npmjs.com (the workflow asks for `id-token: write` for that) or an `NPM_TOKEN` secret. A
  skipped `npm` job means the variable is unset, not that something failed.
- **`release` writes the notes, and the signing step only adds to them.** The workflow's notes carry the
  install and upgrade lines and the changelog; the signing step appends the fingerprint, the hash and the
  verification commands. The signature section is appended rather than written over the top, because the first
  time this was done by hand the changelog disappeared.

## 4. Afterwards

```
gh release view v0.3.8 --json assets    # four assets: tarball, .p7s, .sha256, certificate
```

The check that matters is that GitHub's own reported digest for each asset equals the local hash - an upload
that truncated or re-encoded would otherwise look fine. Then verify the way a reader would: download the
tarball and the `.p7s` from the release and run `docs/verification.md`'s second method against the download,
not against the copy that was signed.

## 5. If a release has to be redone

A tag that is already pushed is a claim somebody may have checked. Prefer a new version. If the tag itself is
wrong (it points at the wrong commit, or the manifest disagrees), delete the tag and the release, fix the cause,
and cut the version again - and say so in the next release's notes, because a moved tag is exactly the kind of
thing a signature is supposed to make visible.
