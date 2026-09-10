// IR-436 - Kerberos Authentication Usage
// Purpose: Baseline or scope successful Kerberos-authenticated logons.
#event_simpleName=UserLogon
AuthenticationPackage=/Kerberos/i
| table([@timestamp,ComputerName,ClientComputerName,UserName,LogonType,UserIsAdmin,AuthenticationPackage],limit=20000)