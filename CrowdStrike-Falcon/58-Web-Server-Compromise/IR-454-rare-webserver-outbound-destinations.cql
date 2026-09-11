// IR-454 - Rare Web Server Outbound Destinations
// Purpose: Surface public destinations contacted by web-server processes with low endpoint prevalence.
#event_simpleName=NetworkConnectIP4
ContextBaseFileName=/(w3wp|httpd|apache2|nginx|php-fpm|php-cgi|java)(\.exe)?$/i
!cidr(RemoteAddressIP4,subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])
| groupBy([ContextBaseFileName,RemoteAddressIP4],function=[count(as=Connections),count(aid,distinct=true,as=Endpoints),collect([ComputerName,RemotePort])],limit=max)
| sort(Endpoints,order=asc)