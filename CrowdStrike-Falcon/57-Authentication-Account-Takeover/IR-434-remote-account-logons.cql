// IR-434 - Remote Account Logons
// Purpose: Surface events Falcon marks as remote-account activity.
#event_simpleName=UserLogon
RemoteAccount=1
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,UserIsAdmin,LogonType,AuthenticationPackage],limit=20000)