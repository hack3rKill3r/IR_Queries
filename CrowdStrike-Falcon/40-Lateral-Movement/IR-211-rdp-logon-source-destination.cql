// IR-211 - RDP Logon Source and Destination
// Purpose: Map source computer to destination host for successful RDP logons.
// MITRE ATT&CK: T1021.001
#event_simpleName=UserLogon
LogonType=10
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserIsAdmin,AuthenticationPackage], limit=20000)