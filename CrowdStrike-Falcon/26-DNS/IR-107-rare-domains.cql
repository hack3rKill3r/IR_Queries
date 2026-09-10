// IR-107 - Rare Domains
// Purpose: Rank domains by query and endpoint prevalence to surface uncommon infrastructure.
#event_simpleName=DnsRequest
| groupBy([DomainName], function=[count(as=QueryCount),count(aid, distinct=true, as=EndpointCount),collect([ComputerName])], limit=max)
| sort(EndpointCount, order=asc)