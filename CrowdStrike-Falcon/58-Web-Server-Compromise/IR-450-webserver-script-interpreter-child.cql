// IR-450 - Web Server Spawning Script Interpreter
// Purpose: Identify Python/Perl/Ruby/PowerShell execution from web-server workers.
#event_simpleName=ProcessRollup2
ParentBaseFileName=/(w3wp|httpd|apache2|nginx|php-fpm|php-cgi|java)/i
FileName=/^(python|python3|perl|ruby|powershell|pwsh)(\.exe)?$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)