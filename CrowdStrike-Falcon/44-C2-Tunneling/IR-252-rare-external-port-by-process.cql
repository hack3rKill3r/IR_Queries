// IR-252 - Rare External Port by Process
// Purpose: Identify uncommon remote ports used by specific processes.
#event_simpleName=NetworkConnectIP4
!cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])
| groupBy([ContextBaseFileName,RemotePort], function=[count(as=Connections),count(aid,distinct=true,as=Endpoints),collect([RemoteAddressIP4,ComputerName])], limit=max)
| sort(Endpoints, order=asc)