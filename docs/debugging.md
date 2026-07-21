# Debugging the auth provider

Diagnosing authentication behavior on a running Openfire that uses
`AdGatedAuthProvider`. Deployment-level issues (pod/init logs, secrets) are in
[openfire-gitops › debugging](https://gitlab.com/mkoese/openfire-gitops/-/blob/main/docs/debugging.md).

## Confirm the provider is active

```
oc exec deployment/<release>-openfire -n openfire -- \
  grep -A1 provider.auth.className /opt/openfire/conf/openfire.xml
```

Or in the admin console → *System Properties*: `provider.auth.className` should be
`com.mkoese.openfire.auth.AdGatedAuthProvider`. If it's the default provider, the
JAR isn't on the classpath — it must be in `/opt/openfire/lib` (not a plugin), and
providers load **before** plugins.

```
oc exec deployment/<release>-openfire -n openfire -- ls /opt/openfire/lib | grep authprovider
```

## Enable auth logging (info / debug / trace)

The provider logs under the `com.mkoese.openfire.auth` category. Raise its level
to see the decision flow — set a `<Logger>` in the image's `log4j2.xml` (live via
`monitorInterval`) as described in
[openfire-oci › logging](https://gitlab.com/mkoese/openfire-oci/-/blob/main/docs/logging.md):

```xml
<Logger name="com.mkoese.openfire.auth" level="debug"/>   <!-- or trace -->
```

**Every line logs usernames, decisions and outcomes only — never a password or
credential** (enforced by `LoggingSafetyTest`).

| Level | Log line | Meaning |
|-------|----------|---------|
| debug | `'<u>' is a local-only user; authenticating against the local store (AD gate bypassed)` | matched `adAuth.localOnlyUsers` (e.g. admin) |
| debug | `Rejecting '<u>': not present in the directory` | AD existence check failed (or LDAP unreachable — fail-closed) |
| debug | `'<u>' exists in AD but has no local account; enrolling` | first login → enrollment path |
| debug | `Rejecting enrollment of '<u>': AD bind failed` | first-login password didn't authenticate against AD |
| info  | `Enrolled new local account '<u>' after AD bind verification` | JIT account created, hash stored |
| debug | `'<u>' authenticated against the local credential store` | normal successful login |
| debug | `'<u>' failed local authentication (stored-hash mismatch)` | wrong local password |
| info  | `Re-enrolling '<u>': local hash mismatch but AD bind succeeded` | only with `adAuth.reenrollOnBindSuccess=true` |
| debug | `Password policy rejected a new password for '<u>': <reason>` | policy violation (reason states the rule, not the password) |
| debug | `Password updated for '<u>'` | password change / enrollment write succeeded |
| trace | `authenticate: evaluating '<u>'` / `SCRAM: serving credentials for '<u>'` | per-request entry points |

For GSSAPI, `AdGatedAuthorizationPolicy` logs `Authorized Kerberos principal '<p>'
as '<u>'` (debug) and the rejection reasons; enable `sasl.gssapi.debug` too.

## Decision flow (what to check for each symptom)

| Symptom | Likely cause | Check |
|---------|--------------|-------|
| **Everyone rejected** | LDAP unreachable → provider fails **closed** | `ldap.host`/`port`/`sslEnabled`, NetworkPolicy egress (389/636/3268/3269), service-account bind (`ldap.adminDN`/password) |
| **A real AD user rejected** | wrong existence lookup | `ldap.baseDN`, `ldap.usernameField` (AD: `sAMAccountName`), `ldap.searchFilter` |
| **First login fails, user exists in AD** | AD bind (enrollment) failing | wrong password, or the account can't simple-bind; test with `ldapsearch -x -D "<userDN>" -w <pw>` |
| **Second login fails after a password change** | DB hash is authoritative and diverged | expected — reset via a new AD-bind enrollment, or set `adAuth.reenrollOnBindSuccess=true` |
| **SCRAM-SHA-1 clients fail but PLAIN works** | user not yet enrolled | SCRAM works from the *second* login on (enrollment needs PLAIN or GSSAPI once) |
| **Admin locked out** | `admin` should bypass AD | ensure `admin` is in `adAuth.localOnlyUsers`; that path uses the local DB hash only |
| **Password change rejected** | password policy | `adAuth.password.minLength`/`minClasses`/`rejectUsername`; the message states which rule failed |

## GSSAPI / Kerberos

GSSAPI is handled by the JDK SASL layer + `AdGatedAuthorizationPolicy`, parallel to
the provider. Turn on `sasl.gssapi.debug = true` and check:

- SPN must be `xmpp/<fqdn>@REALM` and `<fqdn>` in `openfire.xml` must match what
  clients resolve.
- Keytab enctype must match AD (AES256); clock skew < 5 min.
- The principal's realm must be in `sasl.approvedRealms`.
- The user must exist in AD — the policy JIT-creates the local account with a
  random password (so PLAIN stays unusable until the user sets a DB password).

## The empty-password guard (security invariant)

`authenticate()` and `LdapManagerGateway.bind()` both reject empty/blank passwords
**before any LDAP bind** — an AD simple bind with an empty password is an
*unauthenticated bind* that returns success (RFC 4513 §5.1.2). If you ever see an
empty-password login succeed, that guard has regressed — covered by
`rejectsEmptyPasswordBeforeAnyLdapBind` and `LdapManagerGatewayTest`. Never remove it.

## Reproduce locally

Most behavior is unit-testable with mocks (no server) — see
[local-dev.md › Test design](local-dev.md#test-design-no-running-openfire-needed).

## Debugging with breakpoints

### In unit tests (with mocks) — the fast path

**Yes — this is the easiest way to debug the logic.** The tests drive the provider
through the `LdapGateway` / `UserService` / `Settings` / delegate mocks, so you can
set a breakpoint anywhere in `AdGatedAuthProvider` and step through a full flow with
no server, no LDAP, no database.

- **IDE**: open `AdGatedAuthProviderTest`, set a breakpoint (e.g. in `authenticate`
  or `enroll`), right-click the test method → **Debug**. Mockito stubs make each
  branch reproducible — e.g. `enrollsOnFirstLoginWhenAdBindSucceeds` walks the
  enrollment path deterministically.
- **CLI** (attach your IDE to the forked test JVM):
  ```bash
  mvn -Dmaven.surefire.debug test         # listens on port 5005, waits for the debugger
  mvn -Dmaven.surefire.debug -Dtest=AdGatedAuthProviderTest#enrollsOnFirstLoginWhenAdBindSucceeds test
  ```
  Then attach a "Remote JVM Debug" run config to `localhost:5005`.
- To debug a **new** scenario, add a test using the seam constructor and stub the
  mocks for the exact branch you want (see
  [local-dev.md](local-dev.md#test-design-no-running-openfire-needed)) — usually
  faster than reproducing it on a live server.

### Against a running Openfire (remote JDWP)

When you need the *real* server (actual LDAP/AD, real DB), attach a remote debugger
to the Openfire JVM. Append the JDWP agent to `JAVA_OPTS` — the image passes
`JAVA_OPTS` straight to the JVM:

```bash
# podman (local image)
podman run -e JAVA_OPTS="$JAVA_OPTS -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005" \
  -p 9090:9090 -p 5005:5005 openfire-oci:5.1.1
```

```yaml
# gitops values — TEMPORARY, non-prod only
javaOpts:
  - -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005
  # ...keep the existing flags...
```
```bash
oc port-forward deployment/<release>-openfire 5005:5005 -n openfire
```

Then attach your IDE ("Remote JVM Debug" → `localhost:5005`) and set breakpoints in
the provider sources. Build with sources matching the deployed JAR version.

> ⚠️ JDWP is an **unauthenticated debug port** — never enable it in production, and
> never expose 5005 beyond `port-forward` / localhost. `suspend=n` lets Openfire
> start normally; use `suspend=y` only if you must catch very early startup.

### Turn on trace while debugging

Pair breakpoints with `OPENFIRE_LOG_LEVEL_AUTH=trace` (or edit `log4j2.xml`) to see
the decision flow in the logs alongside your stepping — see
[Enable auth logging](#enable-auth-logging-info--debug--trace).
