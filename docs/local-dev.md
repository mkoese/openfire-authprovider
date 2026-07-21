# Local developer environment

Building, testing, and iterating on the auth provider (Java 17 / Maven).

## Prerequisites

- **JDK 17** (build target; newer JDKs compile it but 17 matches the runtime)
- **Maven 3.9+**
- Network access to Maven Central **and** `igniterealtime.org/archiva` (Openfire
  5.x is not on Central) — or an internal mirror, see
  [airgapped-setup.md](airgapped-setup.md)

## Build & test

```bash
mvn verify          # compile + run all unit tests
mvn test            # tests only
mvn -o verify       # offline (after the first successful build populates ~/.m2)
```

The JAR lands in `target/openfire-authprovider-<version>.jar`.

## Behind a Maven mirror that doesn't proxy Ignite Realtime

If your `~/.m2/settings.xml` mirrors `*` to a corporate Nexus that doesn't proxy
`igniterealtime`, resolution of `xmppserver` fails. Use a settings file that
**exempts** the `igniterealtime` repo id declared in `pom.xml`:

```xml
<!-- settings-igniterealtime.xml -->
<settings>
  <mirrors>
    <mirror>
      <id>internal</id>
      <url>https://nexus.internal/repository/maven-public/</url>
      <mirrorOf>*,!igniterealtime</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

```bash
mvn -s settings-igniterealtime.xml verify
```

## Test design (no running Openfire needed)

The provider is built around small seams so the logic is unit-testable without a
live server or database:

| Seam | Production impl | Test |
|------|-----------------|------|
| `LdapGateway` | `LdapManagerGateway` (Openfire `LdapManager`) | Mockito mock |
| `UserService` | `OpenfireUserService` (`UserManager`) | Mockito mock |
| `Settings` | `JiveGlobalsSettings` (`JiveGlobals`) | a `Map::get` lambda |
| `AuthProvider` delegate | `DefaultAuthProvider` | Mockito mock |

So `AdGatedAuthProviderTest` drives the full AD-gate / enrollment / SCRAM-delegation
logic with mocks. `LdapManagerGatewayTest` covers the empty-password guard without
touching `LdapManager`. Add a test by wiring the constructor that takes the seams:

```java
var provider = new AdGatedAuthProvider(delegate, ldap, users, props::get, () -> "chat.example.com");
```

Run a single test class:

```bash
mvn -Dtest=AdGatedAuthProviderTest test
```

## IDE setup

- Import as a Maven project; set the language level to **17**.
- If the IDE can't resolve `org.igniterealtime.openfire:xmppserver`, add the
  Ignite Realtime repository (it's already in `pom.xml`) or run
  `mvn -s settings-igniterealtime.xml dependency:resolve` once from the terminal
  to populate `~/.m2`.

## Testing against a real Openfire

To exercise it end-to-end, build the JAR into the
[openfire-oci](https://gitlab.com/mkoese/openfire-oci) image via `lib.txt` and
deploy with [openfire-gitops](https://gitlab.com/mkoese/openfire-gitops) — the
provider must sit in `/opt/openfire/lib` (not a plugin). See
[debugging.md](debugging.md) for enabling auth logs and reading the flow.

## Snapshot (every main commit)

CI republishes the newest jar under a **stable URL** on every main commit —
for a local `podman build` (drop it into the openfire-oci `lib/` dir), never
for `lib.txt`:

```bash
curl -fsSL -o lib/openfire-authprovider.jar \
  "https://gitlab.com/api/v4/projects/mkoese%2Fopenfire-authprovider/packages/generic/openfire-authprovider/snapshot/openfire-authprovider-snapshot.jar"
```

`lib.txt` accepts released, sha256-pinned versions only — a snapshot never
enters a published image.

## Release

```bash
# bump <version> in pom.xml, commit, then:
git tag v0.2.1 && git push origin main v0.2.1
```

The tag triggers the release pipeline (GitLab package registry + GitHub
release) — its job log prints the **ready-to-paste `lib.txt` line** (URL +
sha256) for openfire-oci. The rest of the chain (image build → digest
promotion dev → preprod → prod) is the
[openfire-gitops upgrade runbook](https://gitlab.com/mkoese/openfire-gitops/-/blob/main/docs/upgrading.md).
