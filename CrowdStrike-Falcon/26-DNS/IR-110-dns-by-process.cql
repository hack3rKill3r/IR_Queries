// IR-110 - DNS by Process
// Purpose: Rank process names by DNS activity for behavioral review.
#event_simpleName=DnsRequest
| groupBy([ContextBaseFileName], function=[count(as=DNSQueryCount),count(DomainName, distinct=true, as=UniqueDomains),collect([DomainName])], limit=max)
| sort(DNSQueryCount, order=desc)