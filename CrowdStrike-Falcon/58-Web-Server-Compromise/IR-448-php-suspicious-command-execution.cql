// IR-448 - PHP Spawning Suspicious Commands
// Purpose: Identify php/php-cgi/php-fpm launching shell or system utilities.
#event_simpleName=ProcessRollup2
ParentBaseFileName=/(php|php-cgi|php-fpm)/i
FileName=/^(cmd|powershell|pwsh|sh|bash|curl|wget|nc|ncat|netcat)$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)