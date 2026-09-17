// IR-509 - Long DNS Label with Measured Shannon Entropy
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Measure entropy in the first DNS label instead of treating length alone as entropy.
// Requires: DnsRequest: DomainName.
// Analyst notes: First-label length 25-63 and entropy >=3.8 are tuning defaults. CDNs, tracking, security agents and encoded identifiers can match. Does not prove DNS tunneling or DGA.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-shannonentropy.html

#event_simpleName=DnsRequest
DomainName=/^(?<FirstLabel>[A-Za-z0-9_-]{25,63})\./
| shannonEntropy(FirstLabel, as=LabelEntropy)
| LabelEntropy>=3.8
| sort(LabelEntropy, order=desc, limit=20000)
| table([@timestamp, aid, ComputerName, ContextProcessId, DomainName, FirstLabel, LabelEntropy], limit=20000)
