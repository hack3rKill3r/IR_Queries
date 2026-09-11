// IR-460 - Web Server Compromise Super Query
// Purpose: Broad hunt for web shells, suspicious web-worker children, web-root writes, and outbound communications.
(
 #event_simpleName=ProcessRollup2
 ParentBaseFileName=/(w3wp|httpd|apache2|nginx|php-fpm|php-cgi|java)(\.exe)?$/i
 FileName=/^(cmd|powershell|pwsh|rundll32|mshta|wscript|cscript|sh|bash|python|perl|ruby|curl|wget)(\.exe)?$/i
)
OR
(
 #event_simpleName=/FileWritten$/
 FilePath=/(\\inetpub\\wwwroot\\|\/var\/www\/|\/usr\/share\/nginx\/html\/|webapps\/)/i
 TargetFileName=/\.(aspx|asp|ashx|php|jsp|jspx|exe|dll|ps1)$/i
)
OR
(
 #event_simpleName=NetworkConnectIP4
 ContextBaseFileName=/(w3wp|httpd|apache2|nginx|php-fpm|php-cgi|java)(\.exe)?$/i
)
| table([@timestamp,#event_simpleName,ComputerName,UserName,ParentBaseFileName,ContextBaseFileName,FileName,FilePath,CommandLine,TargetFileName,RemoteAddressIP4,RemotePort,SHA256HashData],limit=20000)