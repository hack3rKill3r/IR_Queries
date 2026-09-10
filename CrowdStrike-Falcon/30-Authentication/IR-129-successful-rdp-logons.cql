// IR-129 - Successful RDP Logons
// Purpose: Identify successful RemoteInteractive logons.
// Windows LogonType 10 = RemoteInteractive.
#event_simpleName=UserLogon LogonType=10
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,UserIsAdmin,RemoteAccount,AuthenticationPackage], limit=20000)