// IR-256 - Long/High-Entropy-Looking DNS Labels
// Purpose: Surface unusually long DNS labels that may indicate tunneling/DGA activity.
// Analyst note: This is heuristic and needs environmental tuning.
#event_simpleName=DnsRequest
DomainName=/([a-z0-9]{25,}\.)/i
| table([@timestamp,ComputerName,ContextBaseFileName,DomainName,ContextProcessId], limit=20000)