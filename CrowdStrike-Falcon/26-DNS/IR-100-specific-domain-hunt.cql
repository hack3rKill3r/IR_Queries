// IR-100 - Specific Domain Hunt
// Replace SEARCHDOMAIN with a domain, suffix, or escaped regex.
#event_simpleName=DnsRequest DomainName=/SEARCHDOMAIN/i
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,DomainName,IP4Records], limit=20000)