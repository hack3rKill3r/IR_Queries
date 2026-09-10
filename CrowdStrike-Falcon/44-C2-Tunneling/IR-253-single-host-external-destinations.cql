// IR-253 - External Destinations Seen on One Host
// Purpose: Find public destinations contacted by only one endpoint.
#event_simpleName=NetworkConnectIP4
!cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"])
| groupBy([RemoteAddressIP4], function=[count(as=Connections),count(aid,distinct=true,as=EndpointCount),collect([ComputerName,ContextBaseFileName,RemotePort])], limit=max)
| EndpointCount=1
| sort(Connections, order=asc)