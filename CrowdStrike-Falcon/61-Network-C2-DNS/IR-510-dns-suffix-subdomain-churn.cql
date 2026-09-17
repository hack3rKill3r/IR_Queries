// IR-510 - DNS Name Churn Under a Chosen Domain
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Find processes requesting many distinct names under an analyst-selected DNS suffix.
// Requires: DnsRequest: aid, ContextProcessId, DomainName, @timestamp. Replace escaped example.com.
// Analyst notes: The suffix regex uses label boundaries and allows a trailing dot. Fifty names in ten minutes is a review threshold. This does not compute public-suffix/eTLD boundaries.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-math-floor.html
// Reference: https://library.humio.com/crowdstrike-query-language/functions-groupby.html

#event_simpleName=DnsRequest aid=* ContextProcessId=*
DomainName=/(^|\.)example\.com\.?$/i
| lower(DomainName, as=NormalizedDomain)
| WindowStart := @timestamp / 600000
| math:floor(WindowStart, as=WindowStart)
| WindowStart := WindowStart * 600000
| groupBy([aid, ContextProcessId, WindowStart], function=[
    count(as=Requests), count(NormalizedDomain, distinct=true, as=UniqueNames),
    min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
    collect([ComputerName, NormalizedDomain], limit=100)
], limit=max)
| UniqueNames>=50
| sort(UniqueNames, order=desc, limit=20000)
