// IR-455 - DNS Requests from Web Server Processes
#event_simpleName=DnsRequest
ContextBaseFileName=/(w3wp|httpd|apache2|nginx|php-fpm|php-cgi|java)(\.exe)?$/i
| table([@timestamp,ComputerName,ContextBaseFileName,DomainName,IP4Records,ContextProcessId],limit=20000)