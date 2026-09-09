// IR-099 - All DNS Requests
#event_simpleName=DnsRequest
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,DomainName,IP4Records], limit=20000)