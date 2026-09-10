// IR-109 - High-Volume DNS by Host
// Purpose: Identify endpoints generating unusually high DNS volume.
#event_simpleName=DnsRequest
| groupBy([ComputerName], function=[count(as=DNSQueryCount),count(DomainName, distinct=true, as=UniqueDomains)], limit=max)
| sort(DNSQueryCount, order=desc)