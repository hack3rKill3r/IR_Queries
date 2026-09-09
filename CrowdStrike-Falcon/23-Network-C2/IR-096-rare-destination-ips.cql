// IR-096 - Rare Destination IPs
#event_simpleName=NetworkConnectIP4
| groupBy([RemoteAddressIP4], function=[count(as=ConnectionCount),count(aid,distinct=true,as=EndpointCount),collect([ComputerName,ContextBaseFileName])], limit=max)
| sort(EndpointCount, order=asc)