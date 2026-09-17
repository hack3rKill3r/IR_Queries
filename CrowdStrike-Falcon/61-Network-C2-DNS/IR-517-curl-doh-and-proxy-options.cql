// IR-517 - Curl DoH and Explicit Proxy Options
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Review curl commands requesting an alternate resolver or proxy.
// Requires: ProcessRollup2: ImageFileName and CommandLine.
// Analyst notes: Case-sensitive option matching avoids confusing -x with -X. Does not detect all encrypted DNS, environment/config-file proxies, or prove a successful transfer.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://curl.se/docs/manpage.html

#event_simpleName=ProcessRollup2
ImageFileName=/(^|[\\\/])curl(\.exe)?$/i
CommandLine=/(^|\s)(--(?:doh-url|proxy|preproxy|socks4|socks4a|socks5|socks5-hostname)(?:\s|=)|-x\S*)/
| sort(@timestamp, order=asc, limit=20000)
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, SHA256HashData], limit=20000)
