// IR-104 - DNS Requests from Rundll32
// Purpose: Identify DNS activity associated with rundll32.exe.
#event_simpleName=DnsRequest
ContextBaseFileName="rundll32.exe"
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,DomainName,IP4Records,ContextProcessId], limit=20000)