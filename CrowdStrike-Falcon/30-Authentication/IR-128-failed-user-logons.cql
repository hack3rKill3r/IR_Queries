// IR-128 - Failed User Logons
// Purpose: Review failed authentication activity.
#event_simpleName=UserLogonFailed2
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,LogonType,AuthenticationPackage], limit=20000)