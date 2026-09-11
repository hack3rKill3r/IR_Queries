// IR-445 - Script Writes into Common Web Roots
// Purpose: Identify script/web content written into likely web-root locations.
// MITRE ATT&CK: T1505.003
#event_simpleName=/FileWritten$/
FilePath=/(\\inetpub\\wwwroot\\|\/var\/www\/|\/usr\/share\/nginx\/html\/|webapps\/)/i
TargetFileName=/\.(aspx|asp|ashx|php|jsp|jspx|js|ps1|exe|dll)$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath],limit=20000)