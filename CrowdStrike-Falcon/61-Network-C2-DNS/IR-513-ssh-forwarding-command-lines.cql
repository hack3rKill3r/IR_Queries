// IR-513 - SSH and Plink Port-Forwarding Arguments
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Find local, remote and dynamic forwarding switches in native process telemetry.
// Requires: ProcessRollup2: ImageFileName and CommandLine.
// Analyst notes: Argument regex is case-sensitive: -L/-R/-D are not -l/-r/-d. Attached values are included; combined switches and configuration-file-only forwarding can be missed. Legitimate admin use is common.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://man.openbsd.org/ssh

#event_simpleName=ProcessRollup2
ImageFileName=/(^|[\\\/])(ssh|plink)(\.exe)?$/i
CommandLine=/(^|\s)-(?:[LRD](?:\s*\S+)|o\s*["']?(?:LocalForward|RemoteForward|DynamicForward)(?:=|\s))/
| sort(@timestamp, order=asc, limit=20000)
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, ParentProcessId, SHA256HashData], limit=20000)
