// IR-298 - Entra ID MFA Method Changes (Template)
// Purpose: Identify authentication-method registration or modification events.
// NOTE: Requires Entra audit logs. Map action/target fields to your tenant schema.
#Vendor="microsoft"
#event.dataset=/audit/i
action=/(authentication method|MFA|strong authentication|security info)/i
| table([@timestamp,user.name,target.user.name,action,source.ip], limit=20000)