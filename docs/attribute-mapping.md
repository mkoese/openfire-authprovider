# Active Directory attribute mapping

The name in Outlook **is** the AD `displayName` attribute — the chart default
`ldap.nameField: displayName` copies exactly that, so Spark and Outlook show
the same name.

| What | Spark / Openfire | Outlook | AD attribute | Synced? |
|---|---|---|---|---|
| Logon name | Username / JID `jsmith@chat.example.com` | Alias (`CORP\jsmith`) | `sAMAccountName` | ✅ `ldap.usernameField` |
| Full name | Contact list, user search | Display Name | `displayName` (or `{givenName} {sn}`) | ✅ `ldap.nameField` |
| Email | User Email | Primary SMTP | `mail` | ✅ `ldap.emailField` |
| Phone | *View profile* | Business / Mobile | `telephoneNumber` / `mobile` | ❌ vCard, user-editable |
| Title / Department | *View profile* | Job title / Department | `title` / `department` | ❌ vCard, user-editable |
| Photo | Spark avatar | Outlook photo | `thumbnailPhoto` | ❌ vCard, user-editable |

- ✅ rows are written at enrollment and refreshed on every PLAIN/SSO login
  (AD is the source of truth; missing attributes are skipped, never blanked).
- ❌ rows are deliberately not synced: they live in the user-editable vCard.
  Mapping them (`LdapVCardProvider`) would make profiles read-only and add an
  AD query per profile view.

Check a real user before changing any field:

```powershell
Get-ADUser jsmith -Properties displayName,mail |
  Format-List sAMAccountName,displayName,mail
```
