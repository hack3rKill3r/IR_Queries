// IR-449 - Web Server Spawning Curl/Wget
// Purpose: Identify payload retrieval directly from web-server worker contexts.
#event_simpleName=ProcessRollup2
ParentBaseFileName=/(w3wp|httpd|apache2|nginx|php-fpm|php-cgi|java)/i
FileName=/^(curl|wget)(\.exe)?$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)