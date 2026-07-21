# Openfire AD-Gated Auth Provider

Custom [Openfire](https://www.igniterealtime.org/projects/openfire/) 5.x `AuthProvider`: Active Directory gates *who* may log in, while password hashes live in the local database (PostgreSQL). SCRAM-SHA-1, PLAIN and GSSAPI (Kerberos SSO) work in parallel, plus a local admin fallback.

Part of a 3-repo setup:

| Repo | Purpose |
|------|---------|
| [openfire-oci](https://gitlab.com/mkoese/openfire-oci) | Base container image (bakes this JAR into `/opt/openfire/lib` via `lib.txt`) |
| [openfire-gitops](https://gitlab.com/mkoese/openfire-gitops) | Helm chart deployment |
| **openfire-authprovider** | This repo — Java/Maven customizations |

> New here? Start with the [architecture overview](https://gitlab.com/mkoese/openfire-gitops/-/blob/main/docs/architecture.md).

## Authentication flows

**PLAIN (and admin console):**

```
user in adAuth.localOnlyUsers?  ──yes──▶ local DB check (admin fallback)
        │ no
user exists in AD?              ──no───▶ reject
        │ yes
local account exists?           ──no───▶ AD bind with offered password
        │ yes                              ├─ ok: create account, store hash  ✓
        ▼                                  └─ fail: reject
stored hash matches?            ──yes──▶ ✓
        └──no──▶ reject (or re-enroll via AD bind if adAuth.reenrollOnBindSuccess=true)
```

- First password is **bootstrapped via AD bind** — afterwards the **DB hash is authoritative** and may diverge from AD (password changes go through the local policy).
- **SCRAM-SHA-1**: served from the `ofUser` SCRAM columns via `DefaultAuthProvider` delegation. Works from the second login on (enrollment needs PLAIN or GSSAPI once).
- **GSSAPI**: handled by the JDK SASL layer; `AdGatedAuthorizationPolicy` applies the same AD gate and JIT-creates missing accounts with a random password (PLAIN stays unusable until the user sets a real DB password).
- Brute-force lockout is Openfire's built-in `LockOutManager` (runs before any provider).

> **Why not `HybridAuthProvider`?** Its SCRAM getters are broken in Openfire 5.x — verified through 5.1.1 (computed but never returned, then `UserNotFoundException`) — chaining would break SCRAM-SHA-1 for all non-override users.

## Installation

This is **not an Openfire plugin** — providers load before plugins. Place the JAR in `OPENFIRE_HOME/lib/` (the openfire-oci image does this at build time via `lib.txt`). See the official [Custom Authentication Provider guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/implementing-authprovider-guide.html) for the `provider.auth.className` mechanism, and the [LDAP guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/ldap-guide.html) for the `ldap.*` properties this provider's directory gate depends on.

## Configuration (system properties)

```properties
provider.auth.className = com.mkoese.openfire.auth.AdGatedAuthProvider
provider.authorization.classList = com.mkoese.openfire.auth.AdGatedAuthorizationPolicy

# Directory (standard Openfire LDAP settings, used via LdapManager)
ldap.host = dc1.example.com
ldap.port = 636
ldap.sslEnabled = true
ldap.baseDN = OU=Users,DC=example,DC=com
ldap.adminDN = CN=svc-openfire,OU=Service,DC=example,DC=com
ldap.adminPassword = <secret>
ldap.usernameField = sAMAccountName

# PRODUCTION: exclude DISABLED accounts from the gate. Without this clause a
# user disabled in AD keeps authenticating with their locally stored hash
# forever (the DB is authoritative after enrollment) -- offboarding-by-disable
# would not lock anyone out. To gate on a group as well, add a memberOf clause
# (the :1.2.840.113556.1.4.1941: OID matches nested groups):
#   (&(sAMAccountName={0})(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf:1.2.840.113556.1.4.1941:=CN=chat-users,OU=Groups,DC=example,DC=com))
ldap.searchFilter = (&(sAMAccountName={0})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# Profile attributes copied from AD (see "Profile attributes" below)
ldap.nameField = displayName               # -> user Name (Spark contact name)
ldap.emailField = mail                     # -> user Email

# Behavior
adAuth.localOnlyUsers = admin              # bypass the AD gate (local admin)
adAuth.reenrollOnBindSuccess = false       # DB password stays authoritative

# Password policy (local passwords only; AD-verified enrollment is exempt)
adAuth.password.minLength = 12
adAuth.password.minClasses = 3             # of: lower / upper / digit / other
adAuth.password.rejectUsername = true

# Store only SCRAM hashes, no recoverable passwords
user.scramHashedPasswordOnly = true

# SASL
sasl.mechs = PLAIN,SCRAM-SHA-1,GSSAPI
sasl.realm = EXAMPLE.COM                   # default realm applied to bare principals
sasl.approvedRealms = EXAMPLE.COM
```

Kerberos/GSSAPI additionally needs `sasl.gssapi.config` (JAAS file), a keytab for `xmpp/<fqdn>@REALM` and a matching `<fqdn>` in `conf/openfire.xml` — wired by the openfire-gitops chart.

### Profile attributes (how AD attributes are matched)

The Openfire user record has exactly three fields — **Username**, **Name**,
**Email** — and this provider fills all three from AD using Openfire's
**standard LDAP mapping properties** (the same ones `LdapUserProvider` uses):

| Openfire field | Property | AD attribute (typical) | Where you see it |
|---|---|---|---|
| Username (logon name) | `ldap.usernameField` + `{0}` in `ldap.searchFilter` | `sAMAccountName` | the JID `jsmith@chat.example.com`, admin console *Username* |
| Name | `ldap.nameField` (default `cn`) | `displayName`, or template `{givenName} {sn}` | admin console *Name*, Spark user search & contact name |
| Email | `ldap.emailField` (default `mail`) | `mail` | admin console *Email*, Spark profile |

When they are written:

- **Enrollment / JIT creation** (first PLAIN login or first Kerberos SSO): the
  account is created with Name/Email read from AD.
- **Every PLAIN or GSSAPI login**: changed AD values are re-synced (AD is the
  source of truth for the profile, DB stays authoritative for the password).
  SCRAM-SHA-1 reconnects deliberately never touch LDAP, so a rename becomes
  visible on the next full login.
- An attribute **missing in AD** is skipped, never blanked; profile sync is
  fail-open — an LDAP hiccup here can not break a login.

Everything beyond these three fields (avatar, phone, department — what Spark
shows in *View profile*) is the user-editable **vCard**, stored in the DB
(`ofVCard`). Mapping vCards to AD (`LdapVCardProvider`) would make profiles
read-only and add an AD query per profile view — deliberately not used here.

Full AD ↔ Openfire/Spark ↔ Outlook matrix (incl. which AD attributes exist and
how to inspect them): **[docs/attribute-mapping.md](docs/attribute-mapping.md)**.

> **Before go-live, test GSSAPI with a mixed-case `sAMAccountName`** (e.g.
> `JSmith`): JIT enrollment creates the account lowercased, while Openfire's
> follow-up `loadUser` uses the authzid's original casing against a
> case-sensitive lookup — if SSO fails for such users in your environment,
> keep `sAMAccountName`s lowercase (or normalize them) until this is resolved.

### How to set these properties

System properties live in the Openfire **database** (`ofProperty`). Three ways to set them:

1. **OpenShift / Kubernetes — [openfire-gitops](https://gitlab.com/mkoese/openfire-gitops) chart (recommended).**
   Set the `auth.*` and `kerberos.*` values — the chart renders all of the above
   into the conf secret's `openfire.xml` and Openfire seeds them into the DB on
   first boot. Secrets (LDAP service account password) come from Kubernetes
   secrets, never from values:

   ```yaml
   auth:
     enabled: true
     ldap:
       host: dc1.example.com
       baseDN: OU=Users,DC=example,DC=com
       adminDN: CN=svc-openfire,OU=Service,DC=example,DC=com
       existingSecret: openfire-ldap
     password:
       minLength: 12
   ```

2. **Plain [openfire-oci](https://gitlab.com/mkoese/openfire-oci) image (podman, custom manifests).**
   Put the properties in your mounted `conf/openfire.xml` as nested XML elements
   (dots = nesting, e.g. `adAuth.password.minLength` → `<adAuth><password><minLength>`).
   Openfire migrates every non-reserved XML property into DB system properties
   when setup completes — see the
   [openfire-oci › configuration](https://gitlab.com/mkoese/openfire-oci/-/blob/main/docs/configuration.md#system-properties-via-openfirexml)
   for the mechanism and its exceptions.

3. **Runtime changes:** Admin console → *Server Manager → System Properties*.
   XML seeding only happens at setup — after that, the console (or the DB) is
   the source of truth. `provider.auth.className` is applied dynamically on change.

## Build

Java 17. The one non-Central dependency is `org.igniterealtime.openfire:xmppserver`
(scope `provided`), served from the Ignite Realtime archiva repo declared in
`pom.xml`. Three build modes:

### 1. Local build

```bash
mvn verify          # compiles + runs the unit tests
```

Needs reachability to Maven Central and `igniterealtime.org/archiva`. Behind a
corporate Maven mirror that does **not** proxy Ignite Realtime, point Maven at a
settings file that exempts the `igniterealtime` repo id from the mirror:

```bash
mvn -s settings-igniterealtime.xml verify
# mirror: <mirrorOf>*,!igniterealtime</mirrorOf>
```

### 2. GitLab CI (with internet)

`.gitlab-ci.yml` runs `mvn verify` on every push/MR (UBI9 OpenJDK 17 image,
cached `.m2`). On a tag (`v0.1.1`) the `release` job uploads the JAR to the
GitLab **generic package registry**:

```
/api/v4/projects/mkoese%2Fopenfire-authprovider/packages/generic/openfire-authprovider/<tag>/openfire-authprovider-<version>.jar
```

and prints the sha256 to pin in openfire-oci `lib.txt`. A GitHub Actions mirror
attaches the JAR + `SHA256SUMS` to a GitHub release.

### 3. Airgapped GitLab (self-hosted, no internet)

The runner reaches only your internal Maven repository, which must host the
**6 Ignite-Realtime artifacts** not on Maven Central. Full seeding recipe (both
"Nexus proxies Central" and "fully airgapped" cases): **[docs/airgapped-setup.md](docs/airgapped-setup.md)**.

## Documentation

| Doc | What |
|-----|------|
| [docs/attribute-mapping.md](docs/attribute-mapping.md) | AD ↔ Openfire/Spark ↔ Outlook attribute mapping, what is (not) synced |
| [docs/local-dev.md](docs/local-dev.md) | Build, test, IDE setup, the test seams, releasing |
| [docs/airgapped-setup.md](docs/airgapped-setup.md) | Internal Maven mirror + the 6-artifact Nexus seed |
| [docs/debugging.md](docs/debugging.md) | Auth-flow logging, LDAP/SCRAM/GSSAPI troubleshooting |

## License

[Apache License 2.0](LICENSE)
