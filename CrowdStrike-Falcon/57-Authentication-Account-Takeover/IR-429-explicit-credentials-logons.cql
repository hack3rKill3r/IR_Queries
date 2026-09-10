// IR-429 - Explicit Credentials / NewCredentials Logons
// Windows LogonType 9 = NewCredentials.
#event_simpleName=UserLogon
LogonType=9
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,UserIsAdmin,AuthenticationPackage],limit=20000)