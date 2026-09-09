// IR-073 - High-Interest Processes on a Host
// Replace VICTIM-HOST with the endpoint under investigation.
#event_simpleName=ProcessRollup2 ComputerName="VICTIM-HOST"
FileName=/^(powershell|pwsh|cmd|wmic|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|schtasks|sc|nltest|whoami|net|net1|dsquery|mstsc|psexec|psexec64|rclone|7z|rar|winrar|vssadmin|wbadmin|bcdedit)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)