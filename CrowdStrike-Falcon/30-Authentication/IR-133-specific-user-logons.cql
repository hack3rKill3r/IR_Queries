// IR-133 - Specific User Logons
// Replace COMPROMISED-USER with the account under investigation.
#event_simpleName=UserLogon UserName="COMPROMISED-USER"
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,UserIsAdmin,RemoteAccount,LogonType,AuthenticationPackage], limit=20000)