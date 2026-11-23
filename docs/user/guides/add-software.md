---
layout: default
title: Add software
---

# Add software

Vapor installs software from Ubuntu packages. A package can also provide named
groups of its files, and each group is called a slice. A slice puts only its own
files in the image, so nothing unasked for comes along.

You have three ways to fill an image, and one image can use all of them:

| Way       | Use when                                                         |
| --------- | ---------------------------------------------------------------- |
| Slices    | The files you need are described by the Ubuntu Chisel catalogue. |
| Packages  | You want every file of the package, not a described subset.      |
| Artifacts | You ship your own binary or archive.                             |

## Slices

The Chisel catalogue for Ubuntu describes which files each slice contains:

```yaml
contents:
  catalogues:
    - name: ubuntu
      url: https://github.com/canonical/chisel-releases
      branch: ubuntu-26.04
  slices:
    - package: ca-certificates
      slice: data-with-certs
```

`vaporize lock` fetches that repository once and saves the exact commit. Builds
read the saved copy, so they never contact GitHub.

### Find the slice you need

The `slices` commands read a catalogue you already have on disk:

```bash
git clone --depth 1 --branch ubuntu-26.04 \
  https://github.com/canonical/chisel-releases catalogue

vaporize slices list --catalogue catalogue
vaporize slices list --catalogue catalogue --package ca-certificates
vaporize slices show ca-certificates/data-with-certs --catalogue catalogue
```

```text
package: base-files
slice: release-info
essential:
  base-files_copyright
  base-files_etc
  base-files_lib
contents:
  /etc/debian_version copy ""
  /etc/host.conf copy ""
  /etc/os-release copy ""
  ...
```

`show` prints the slice definition. The paths are the files that slice puts in the
image, and `essential` names the slices it needs as well. Those are pulled in
automatically, so you do not list them yourself.

`vaporize slices check --catalogue catalogue` validates a whole catalogue and
prints `catalogue OK` when every definition parses.

### Slices are resolved for you

Write one slice and Vapor adds everything that slice requires:

```yaml
contents:
  slices:
    - package: base-files
      slice: release-info
```

That pulls in the copyright notices, `/etc` and `/lib` files the slice needs. You
never list essential slices by hand.

A slice can only be selected once. Two slices from the same package are fine:

```yaml
contents:
  slices:
    - package: ca-certificates
      slice: data-with-certs
    - package: ca-certificates
      slice: copyright
```

### Versions

Pin a package version when a newer one breaks your image:

```yaml
contents:
  slices:
    - package: tzdata
      slice: eurasia
      version: "= 2024a"
```

Every version needs an operator, and the common ones read the way you expect:
`= 3.0.13` takes that release, `~> 3.0` stays on the 3.x line, and
`>= 1.4, < 1.5` holds between two versions. The
[contents reference](../reference/contents.md#versions) lists them all.

Ubuntu removes old versions over time, so a version that has disappeared can only
be rebuilt from a cache that already holds it. A range keeps working for longer,
because a newer build of the same release still matches.

## Whole packages

Sometimes you want the complete package:

```yaml
contents:
  packages:
    - busybox-static
    - name: openssl
      version: "~> 3.0"
```

An unpinned package is just its name. A pinned package keeps the mapping form,
because the version needs a place to go: writing the pin as `- openssl: "3.0.13-1ubuntu1"`
is refused.

Whole packages bring their maintainer scripts and their full file list. Slices
usually give you a smaller image, so prefer a slice when one exists.

Maintainer scripts are data in Vapor, never code it runs. Whatever a script
would have done — creating a user, writing a config, registering a service —
you declare yourself, and Vapor writes it deterministically:

- users and groups: `filesystem.accounts` (see
  [configure the system](configure-the-system.md#users-and-groups));
- files, directories and links: `filesystem.paths`;
- timezone, certificates, release identity: the matching `filesystem` fields;
- the package database, and the apt sandbox account (`_apt`) plus the source list
  when `hardening.keep-package-sources` is on: Vapor writes these itself from the
  verified package metadata, the same records the scripts would have produced.

Anything else a script would have done is simply absent from the image. There is
no list of accepted exceptions: a specification that tries to declare one is
refused at load time.

If you need scripted changes to package content, use a slice instead of the
whole package. A slice can carry its own small mutation script, and Vapor runs
those — inside a sandbox, with limits on memory, time and output you cannot
change (see [reference: policies](../reference/policies.md#slices-engine)). The
catalogue authors write those scripts to adjust exactly the files the slice
ships, which is usually a safer and smaller way to get the result than the
whole package's maintainer scripts would be.

A package cannot be requested both whole and through a slice:

```text
vaporize: operation failed: load spec "image.yaml": validate spec: whole-package/slice overlap is not allowed
```

## Choose where packages come from

Every package comes from a repository. An Ubuntu specification needs one declared:
the starter that `vaporize init --distro ubuntu` writes declares the public Ubuntu
archive, which covers `main` and `universe` for the suites of your release. A
Debian specification declares none, because Vapor already serves both Debian
archives for a release it has reviewed.

Declare your own repository when you need suites, components or a mirror:

```yaml
contents:
  repositories:
    - name: mirror
      endpoints:
        - platforms: [linux/amd64]
          url: https://archive.example.com/ubuntu
      suites: [resolute, resolute-updates]
      components: [main, universe]
```

A repository needs at least one endpoint, a suite list and a component list.
`vaporize lock` verifies the signed metadata against the keys for that repository
before it downloads a package.

To use a software vendor's repository alongside the distribution archive,
[add a third-party DEB repository](add-third-party-repositories.md).

A catalogue names an archive for each of its slices. Ubuntu's catalogue declares
the public archive plus two paid ones. A catalogue archive is used only when a
repository is bound to it:

```yaml
contents:
  catalogues:
    - name: ubuntu
      url: https://github.com/canonical/chisel-releases
      branch: ubuntu-26.04
      archives:
        ubuntu: mirror
```

Without a binding, the archive named after the distribution (`ubuntu`) uses the
Ubuntu archive and the paid ones are skipped, so the starter specification locks
with no bindings at all. Any other archive needs a binding even when no slice uses
it:

```text
vaporize: operation failed: catalogue "custom": catalogue archive "internal" requires an explicit repository binding
```

See [use private packages](use-private-packages.md) for the paid archives.

## Order and repetition

Order does not matter for a build, and the result is the same either way. The same
package or the same slice may not be requested twice:

```text
vaporize: operation failed: load spec "image.yaml": validate spec: duplicate whole package request
vaporize: operation failed: load spec "image.yaml": validate spec: duplicate slice request
```

Two different slices of one package are fine.

## Next

- [Add your own files](add-your-own-files.md) ships a binary without a package.
- [Reference: contents](../reference/contents.md) lists every field.
