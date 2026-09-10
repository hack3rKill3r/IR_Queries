// IR-139 - RDP Logons by User
// Replace USERNAME with the account under investigation.
#event_simpleName=UserLogon LogonType=10 UserName="USERNAME"
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,UserIsAdmin,RemoteAccount,AuthenticationPackage], limit=20000)