// IR-257 - High-Volume DNS by Host
// Purpose: Surface endpoints generating large volumes of DNS requests.
#event_simpleName=DnsRequest
| groupBy([ComputerName], function=[count(as=DNSRequests),count(DomainName,distinct=true,as=UniqueDomains),collect([ContextBaseFileName])], limit=max)
| sort(DNSRequests, order=desc)