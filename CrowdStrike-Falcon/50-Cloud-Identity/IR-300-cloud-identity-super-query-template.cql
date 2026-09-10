// IR-300 - Cloud Identity Super Query (Template)
// Purpose: Broad hunt for failed sign-ins, MFA/security-info changes, role changes, and suspicious identity events.
// NOTE: Requires Entra/Okta logs in Falcon Next-Gen SIEM. Normalize these placeholders to your parser fields.
(#Vendor="microsoft" OR #Vendor="okta")
(
  outcome=/fail/i
  OR action=/(role assignment|Add member to role|authentication method|MFA|security info|password reset|credential)/i
  OR event.type=/(authentication|user\.session|policy|factor)/i
)
| table([@timestamp,#Vendor,user.name,target.user.name,source.ip,source.geo.country,outcome,action,event.type,reason,application], limit=20000)