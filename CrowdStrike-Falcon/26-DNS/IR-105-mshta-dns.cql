// IR-105 - DNS Requests from MSHTA
// Purpose: Identify DNS activity associated with mshta.exe.
#event_simpleName=DnsRequest
ContextBaseFileName="mshta.exe"
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,DomainName,IP4Records,ContextProcessId], limit=20000)