// IR-325 - AMSI Bypass Strings
// Purpose: Hunt for common PowerShell AMSI bypass indicators.
// MITRE ATT&CK: T1562.001
#event_simpleName=ProcessRollup2
CommandLine=/(amsiInitFailed|AmsiUtils|amsiContext|AmsiScanBuffer|System\.Management\.Automation\.AmsiUtils)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)