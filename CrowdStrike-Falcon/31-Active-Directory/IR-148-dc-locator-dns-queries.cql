// IR-148 - Domain Controller Locator DNS Queries
// Purpose: Identify nslookup queries for LDAP/Kerberos service records.
// MITRE ATT&CK: T1018
#event_simpleName=ProcessRollup2
FileName="nslookup.exe"
CommandLine=/(_ldap\._tcp|_kerberos\._tcp)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)