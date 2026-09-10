// IR-103 - DNS Requests from CMD
// Purpose: Identify DNS requests associated with cmd.exe.
#event_simpleName=DnsRequest
ContextBaseFileName="cmd.exe"
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,DomainName,IP4Records,ContextProcessId], limit=20000)