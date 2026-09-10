// IR-251 - Rare External Destination by Process
// Purpose: Identify uncommon public IP destinations per process.
#event_simpleName=NetworkConnectIP4
!cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16"])
| groupBy([ContextBaseFileName,RemoteAddressIP4], function=[count(as=Connections),count(aid,distinct=true,as=Endpoints),collect([ComputerName,RemotePort])], limit=max)
| sort(Endpoints, order=asc)