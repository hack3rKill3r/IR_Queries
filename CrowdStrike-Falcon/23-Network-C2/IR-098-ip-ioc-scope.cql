// IR-098 - Scope Specific Remote IP Across Estate
// Replace IOC_IP with the remote IPv4 indicator.
#event_simpleName=NetworkConnectIP4 RemoteAddressIP4="IOC_IP"
| groupBy([RemoteAddressIP4], function=[count(as=ConnectionCount),count(aid,distinct=true,as=EndpointCount),collect([ComputerName,ContextBaseFileName])], limit=max)