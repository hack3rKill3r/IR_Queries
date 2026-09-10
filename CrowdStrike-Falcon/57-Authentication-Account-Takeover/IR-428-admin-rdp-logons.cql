// IR-428 - Administrative RDP Logons
// Purpose: Identify RDP logons performed by accounts marked as administrators.
#event_simpleName=UserLogon
LogonType=10
UserIsAdmin=1
| table([@timestamp,ComputerName,ClientComputerName,UserName,UserSid,AuthenticationPackage],limit=20000)