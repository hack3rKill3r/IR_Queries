// IR-297 - Entra ID Administrative Role Changes (Template)
// Purpose: Identify privileged role assignment/removal events.
// NOTE: Requires Entra audit logs. Map action/user fields to your parser.
#Vendor="microsoft"
#event.dataset=/audit/i
action=/(Add member to role|Add eligible member to role|role assignment|Remove member from role)/i
| table([@timestamp,user.name,target.user.name,action,source.ip], limit=20000)