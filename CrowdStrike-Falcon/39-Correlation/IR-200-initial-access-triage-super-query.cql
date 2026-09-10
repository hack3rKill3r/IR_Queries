// IR-200 - Initial Access Triage Super Query
// Purpose: Broad initial-access hunt for Office/browser/explorer spawning interpreters, LOLBins, downloaders, or MSI execution.
#event_simpleName=ProcessRollup2
ParentBaseFileName=/^(winword|excel|powerpnt|outlook|chrome|msedge|firefox|brave|explorer)\.exe$/i
FileName=/^(cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl|msiexec)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData,TargetProcessId,ParentProcessId], limit=20000)