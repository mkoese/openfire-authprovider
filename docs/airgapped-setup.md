# Airgapped build & Nexus seeding

Building the provider JAR where the CI runner reaches only your **internal Maven
repository** (Nexus/Artifactory). Openfire 5.x is **not on Maven Central**, so a
Central-only mirror will fail to resolve `xmppserver` — you must seed the Ignite
Realtime artifacts.

Companion guides: [openfire-oci airgapped build](https://gitlab.com/mkoese/openfire-oci/-/blob/main/docs/airgapped-setup.md)
(where this JAR is consumed) and
[openfire-gitops airgapped deploy](https://gitlab.com/mkoese/openfire-gitops/-/blob/main/docs/airgapped-setup.md).

## Point Maven at the internal repo

Commit a `ci/settings.xml` (or a masked `MAVEN_SETTINGS` file variable) that
mirrors `*` to your internal `maven-public` group, and build with it:

```bash
mvn -s ci/settings.xml verify
```

The release job pushes the JAR to the **internal GitLab's own** package registry
(`CI_API_V4_URL` + `CI_JOB_TOKEN`) — no external network needed.

## Capture the exact closure (once, on a connected host)

Build into a **clean throwaway repo** so you capture exactly this project's
dependencies + plugins + test libs — not your whole personal `~/.m2`:

```bash
mvn -s ci/settings.xml -Dmaven.repo.local=./airgap-m2 verify
# ./airgap-m2 ≈ 118 MB, 226 jars for Openfire 5.1.1
```

## What to seed — depends on what Nexus can still proxy

### A) Nexus proxies Maven Central but not Ignite Realtime

Seed only the **6 archiva-only artifacts** (~6 MB) that Central does not host;
everything else resolves through the Central proxy:

| GAV | files |
|-----|-------|
| `org.igniterealtime.openfire:xmppserver:5.1.1` | jar + pom |
| `org.igniterealtime.openfire:parent:5.1.1` | pom |
| `org.igniterealtime.openfire:i18n:5.1.1` | jar + pom |
| `org.igniterealtime:tinder:2.1.0` | jar + pom |
| `com.cenqua.shaj:shaj:0.5` | jar + pom |
| `org.gnu.inet:libidn:1.35` | jar + pom |

```bash
for g in org/igniterealtime/openfire/xmppserver/5.1.1 \
         org/igniterealtime/openfire/parent/5.1.1 \
         org/igniterealtime/openfire/i18n/5.1.1 \
         org/igniterealtime/tinder/2.1.0 \
         com/cenqua/shaj/shaj/0.5 org/gnu/inet/libidn/1.35; do
  for f in ./airgap-m2/$g/*.jar ./airgap-m2/$g/*.pom; do
    [ -e "$f" ] && curl -sf -u "$NEXUS_USER:$NEXUS_PASS" \
      --upload-file "$f" "$NEXUS/repository/maven-thirdparty/$g/$(basename "$f")"
  done
done
```

> The list is verified from Maven's `_remote.repositories` provenance markers
> (each archiva-sourced file is tagged `>igniterealtime=`). Re-derive it after an
> Openfire bump: `grep -rl ">igniterealtime=" ./airgap-m2 --include=_remote.repositories`.

### B) Fully airgapped (no Central proxy either)

Transfer the whole `./airgap-m2` and bulk-upload it (skip resolver metadata):

```bash
find ./airgap-m2 -type f ! -name '*.lastUpdated' ! -name '_remote.repositories' \
  ! -name 'resolver-status.properties' ! -name 'maven-metadata-*.xml' |
while read -r f; do
  curl -sf -u "$NEXUS_USER:$NEXUS_PASS" --upload-file "$f" \
    "$NEXUS/repository/maven-thirdparty/${f#./airgap-m2/}"
done
```

## Wire the hosted repo into the group

Add the `maven-thirdparty` hosted repo to your `maven-public` **group** so
`ci/settings.xml` (which mirrors `*` → `maven-public`) resolves both proxied and
seeded artifacts.

## Publishing the JAR to openfire-oci

The airgapped `openfire-oci` build pulls this JAR from `lib.txt`. Point that pin
at the internal GitLab package registry URL (the `sha256` stays valid — see
[openfire-oci airgapped build](https://gitlab.com/mkoese/openfire-oci/-/blob/main/docs/airgapped-setup.md)).
