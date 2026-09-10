// IR-130 - Network Logons
// Purpose: Identify successful network logons.
// Windows LogonType 3 = Network.
#event_simpleName=UserLogon LogonType=3
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,UserIsAdmin,RemoteAccount,AuthenticationPackage], limit=20000)