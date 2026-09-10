// IR-117 - Script and HTA Files Written
// Purpose: Identify common Windows script payload types written to disk.
#event_simpleName=/FileWritten$/
TargetFileName=/\.(vbs|vbe|js|jse|wsf|hta)$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)