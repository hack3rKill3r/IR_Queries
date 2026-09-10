// IR-258 - DNS Process Diversity
// Purpose: Find processes resolving unusually many distinct domains.
#event_simpleName=DnsRequest
ContextBaseFileName=*
| groupBy([ContextBaseFileName], function=[count(as=DNSRequests),count(DomainName,distinct=true,as=UniqueDomains),count(aid,distinct=true,as=Endpoints)], limit=max)
| sort(UniqueDomains, order=desc)