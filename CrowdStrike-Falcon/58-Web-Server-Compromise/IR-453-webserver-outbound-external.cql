// IR-453 - Web Server Outbound External Connections
// Purpose: Identify outbound connections from web-server processes.
#event_simpleName=NetworkConnectIP4
ContextBaseFileName=/(w3wp|httpd|apache2|nginx|php-fpm|php-cgi|java)(\.exe)?$/i
!cidr(RemoteAddressIP4,subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,RemoteAddressIP4,RemotePort,ContextProcessId],limit=20000)