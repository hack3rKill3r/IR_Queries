// IR-101 - Suspicious TLD DNS Hunt
// Purpose: Hunt DNS requests for a TLD or suffix of interest.
// Replace .ru with the suffix relevant to the investigation.
#event_simpleName=DnsRequest
DomainName=/\.ru$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,DomainName,IP4Records,ContextProcessId], limit=20000)