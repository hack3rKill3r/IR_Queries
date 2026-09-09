// IR-097 - Rare Destination Ports
#event_simpleName=NetworkConnectIP4
| groupBy([RemotePort], function=[count(as=ConnectionCount),count(aid,distinct=true,as=EndpointCount),collect([ComputerName,ContextBaseFileName])], limit=max)
| sort(EndpointCount, order=asc)