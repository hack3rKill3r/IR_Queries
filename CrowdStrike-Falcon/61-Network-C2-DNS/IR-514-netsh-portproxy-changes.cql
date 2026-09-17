// IR-514 - Netsh Portproxy Add or Set Commands
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Find command-line attempts to create or modify Windows TCP forwarding rules.
// Requires: ProcessRollup2: ImageFileName and CommandLine.
// Analyst notes: A command line does not prove the rule was applied. Abbreviated netsh commands and registry/API-based changes are not covered; inspect rule state and related network events.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface

#event_simpleName=ProcessRollup2 event_platform=Win
ImageFileName=/\\netsh\.exe$/i
CommandLine=/\binterface\s+portproxy\s+(add|set)\b/i
| sort(@timestamp, order=asc, limit=20000)
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId], limit=20000)
