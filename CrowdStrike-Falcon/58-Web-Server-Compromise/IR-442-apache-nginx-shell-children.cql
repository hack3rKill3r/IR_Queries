// IR-442 - Apache/Nginx Spawning Shells
// Purpose: Identify web-server worker processes launching shells/interpreters.
// MITRE ATT&CK: T1505.003
#event_simpleName=ProcessRollup2
ParentBaseFileName=/(httpd|apache2|nginx|php-fpm|php-cgi)/i
FileName=/^(cmd|powershell|pwsh|sh|bash|zsh|python|perl|ruby)\.exe$|^(sh|bash|zsh|python|perl|ruby)$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)