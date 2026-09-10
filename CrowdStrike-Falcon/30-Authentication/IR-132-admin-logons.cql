// IR-132 - Administrative Logons
// Purpose: Identify successful logons where Falcon marks the user as an administrator.
#event_simpleName=UserLogon UserIsAdmin=1
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,LogonType,RemoteAccount,AuthenticationPackage], limit=20000)