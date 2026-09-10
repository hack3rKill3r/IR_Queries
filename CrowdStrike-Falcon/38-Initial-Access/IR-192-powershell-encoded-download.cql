// IR-192 - Encoded PowerShell with Network Indicator
// Purpose: Identify encoded PowerShell that also contains network/download indicators.
// MITRE ATT&CK: T1027 / T1059.001 / T1105
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
CommandLine=/\s-(e|enc|encodedcommand)\s/i
CommandLine=/(http|https|download|webclient|invoke-webrequest|iwr|irm)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)