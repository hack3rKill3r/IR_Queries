// IR-184 - ClickFix-Style Explorer -> Shell/LOLBin
// Purpose: Identify explorer.exe launching interpreters/LOLBins with suspicious download or execution strings.
// MITRE ATT&CK: T1204.004 / T1059 / T1105
#event_simpleName=ProcessRollup2
ParentBaseFileName="explorer.exe"
FileName=/^(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|wmic|msbuild|installutil|bitsadmin|curl|ftp|certutil)\.exe$/i
CommandLine=/(iex|irm|iwr|invoke-webrequest|https?:\/\/|ftp|smb|download|encodedcommand|bypass|invoke-expression|frombase64string|start-process|new-object)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)