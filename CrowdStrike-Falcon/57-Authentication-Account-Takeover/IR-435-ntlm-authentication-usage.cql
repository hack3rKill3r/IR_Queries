// IR-435 - NTLM Authentication Usage
// Purpose: Identify successful logons using NTLM for lateral-movement review.
#event_simpleName=UserLogon
AuthenticationPackage=/NTLM/i
| table([@timestamp,ComputerName,ClientComputerName,UserName,LogonType,UserIsAdmin,AuthenticationPackage],limit=20000)