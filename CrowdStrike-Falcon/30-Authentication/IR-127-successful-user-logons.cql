// IR-127 - Successful User Logons
// Purpose: Review successful authentication activity.
#event_simpleName=UserLogon
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,UserIsAdmin,RemoteAccount,LogonType,AuthenticationPackage], limit=20000)