// IR-069 - CMD to PowerShell Process Lineage
// Purpose: Correlate cmd.exe spawning PowerShell on the same endpoint.
correlate(
  {#event_simpleName=ProcessRollup2 FileName="cmd.exe" | rename(field="TargetProcessId", as="cmdPID")},
  {#event_simpleName=ProcessRollup2 FileName=/^(powershell|pwsh)\.exe$/i | rename(field="ParentProcessId", as="cmdPID")},
  field=[aid,cmdPID], sequence=true, within=10m
)