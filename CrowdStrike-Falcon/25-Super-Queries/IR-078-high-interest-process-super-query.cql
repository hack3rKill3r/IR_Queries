// IR-078 - High-Interest Process Super Query
// Purpose: Broad first-pass hunt for frequently abused administrative, scripting, discovery, staging, and recovery tools.
#event_simpleName=ProcessRollup2
| in(field="FileName", ignoreCase=true, values=["powershell.exe","pwsh.exe","cmd.exe","wmic.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","wscript.exe","cscript.exe","msbuild.exe","installutil.exe","schtasks.exe","sc.exe","nltest.exe","whoami.exe","net.exe","net1.exe","dsquery.exe","mstsc.exe","psexec.exe","psexec64.exe","rclone.exe","7z.exe","rar.exe","winrar.exe","vssadmin.exe","wbadmin.exe","bcdedit.exe"])
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)