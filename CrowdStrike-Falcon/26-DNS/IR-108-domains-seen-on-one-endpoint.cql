// IR-108 - Domains Seen on One Endpoint
// Purpose: Surface domains with very low estate prevalence.
#event_simpleName=DnsRequest
| groupBy([DomainName], function=[count(as=QueryCount),count(aid, distinct=true, as=EndpointCount),collect([ComputerName,ContextBaseFileName])], limit=max)
| EndpointCount=1
| sort(QueryCount, order=desc)