// IR-131 - New Credentials / RunAs Logons
// Purpose: Identify LogonType 9 activity, useful for RunAs and explicit-credential investigations.
#event_simpleName=UserLogon LogonType=9
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,UserIsAdmin,RemoteAccount,AuthenticationPackage], limit=20000)