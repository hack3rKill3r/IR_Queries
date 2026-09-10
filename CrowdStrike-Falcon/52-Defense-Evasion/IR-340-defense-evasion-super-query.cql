// IR-340 - Defense Evasion / EDR Impairment Super Query
// Purpose: Broad first-pass hunt for security control impairment and evasion.
#event_simpleName=ProcessRollup2
(
 CommandLine=/(DisableRealtimeMonitoring|ExclusionPath|ExclusionProcess|amsiInitFailed|AmsiScanBuffer|ScriptBlockLogging|Clear-EventLog|wevtutil.*\bcl\b|auditpol.*\/clear|advfirewall.*state.*off|Set-NetFirewallProfile.*False|timestomp|EtwEventWrite|CreateRemoteThread|WriteProcessMemory)/i
 OR
 (
  FileName=/^(sc|net|net1|taskkill)\.exe$/i
  CommandLine=/(falcon|crowdstrike|defender|sense|sentinel|sophos|carbonblack|elastic|security)/i
 )
)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)