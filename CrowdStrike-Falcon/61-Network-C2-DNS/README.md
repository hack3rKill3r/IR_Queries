# IR-501–520: Network discovery, C2 candidates, tunneling and DNS

Twenty **native Falcon sensor-telemetry hunting queries**. These are not Entra, Okta or other third-party parser templates.

**Validation status:** Draft hunts. References were reviewed and local regex examples and arithmetic checks were run. The queries have **not** been executed by a Falcon CQL parser or tested against a customer tenant. A match is an investigation lead, not a confirmed incident. Earlier library files were not audited as part of this batch.

## Start here

Run IR-501 to list the fields that actually exist, then IR-502 to see field coverage by event family. Use a short search window and the view/repository containing Falcon sensor events. To inspect a representative record, run:

```text
#event_simpleName=NetworkConnectIP4
| head(5)
```

Expand a result and inspect its fields before adding conditions. No results can mean the wrong time window, view, access permissions or missing telemetry; it does not establish absence of malicious activity. Run IR-501 against a single event family when checking a field needed by that family. Diagnostic `With*` counts in IR-502 measure field presence, not whether values are nonempty or meaningful.

Expected native relationships are `ProcessRollup2.TargetProcessId` to `NetworkConnectIP4.ContextProcessId`, `NetworkListenIP4.ContextProcessId` or `DnsRequest.ContextProcessId`, with the **same `aid`**. Use Falcon's process identifiers, not a Windows PID or `RawProcessId`. Image-based filters use `ImageFileName`; network/DNS events are not assumed to contain a process name or username. Ports are `LocalPort`/`RemotePort` in this pack. IR-502 also checks `LPort`/`RPort` diagnostically, but they are not silently treated as interchangeable.

Replace every `REPLACE_*` value before running a scoped query. IR-510 uses an escaped `example.com` domain that must be replaced with the investigation domain. It deliberately matches DNS label boundaries rather than any occurrence of the text. Run in a single-customer data scope; do not join unrelated customer data.

## Query index

| ID | Query |
|---|---|
| IR-501 | [Network and DNS Field Discovery](IR-501-network-dns-field-discovery.cql) |
| IR-502 | [Native Field Coverage by Event Type](IR-502-network-dns-field-coverage.cql) |
| IR-503 | [Horizontal TCP Fan-Out in Five Minutes](IR-503-horizontal-tcp-fanout.cql) |
| IR-504 | [Vertical TCP Port Fan-Out in Five Minutes](IR-504-vertical-tcp-port-fanout.cql) |
| IR-505 | [Internal Management-Port Fan-Out](IR-505-internal-management-port-fanout.cql) |
| IR-506 | [Interpreter or LOLBin to IPv4 Connection](IR-506-interpreter-network-correlation.cql) |
| IR-507 | [Repeated Destination Activity Across Time Windows](IR-507-repeated-destination-active-windows.cql) |
| IR-508 | [Connection Interval Analysis for One Process and Destination](IR-508-single-tuple-connection-intervals.cql) |
| IR-509 | [Long DNS Label with Measured Shannon Entropy](IR-509-dns-long-label-entropy.cql) |
| IR-510 | [DNS Name Churn Under a Chosen Domain](IR-510-dns-suffix-subdomain-churn.cql) |
| IR-511 | [Port 53 Connections to Non-RFC1918 Destinations](IR-511-dns-port-non-rfc1918-destinations.cql) |
| IR-512 | [Interpreter or LOLBin to DNS Request](IR-512-interpreter-dns-correlation.cql) |
| IR-513 | [SSH and Plink Port-Forwarding Arguments](IR-513-ssh-forwarding-command-lines.cql) |
| IR-514 | [Netsh Portproxy Add or Set Commands](IR-514-netsh-portproxy-changes.cql) |
| IR-515 | [Named Tunneling Tool to IPv4 Listener](IR-515-tunnel-process-listener-correlation.cql) |
| IR-516 | [Process with Listener and Outbound Connection](IR-516-listener-and-outbound-same-process.cql) |
| IR-517 | [Curl DoH and Explicit Proxy Options](IR-517-curl-doh-and-proxy-options.cql) |
| IR-518 | [IPv4 IOC Scoping by Endpoint and Process](IR-518-ipv4-ioc-process-scoping.cql) |
| IR-519 | [Named Scanner Process to Observed Connection](IR-519-scanner-process-network-correlation.cql) |
| IR-520 | [Process-Centric Network and DNS Timeline](IR-520-process-centric-network-dns-timeline.cql) |

## Investigation paths

**Possible scanning:** Run IR-503/504/505, take `aid` and `ContextProcessId`, and pivot to IR-520. IR-519 adds execution evidence for named scanner tools, but raw-packet scanning can be absent from ordinary connection events. Check the authorized scanning and management baseline.

**Possible beaconing:** IR-507 finds repeated contact in multiple five-minute windows; those windows need not be consecutive. Run IR-508 on exactly one endpoint/process/destination/port tuple to examine event-to-event timing. Low interval variability is compatible with legitimate polling and monitoring. Event loss, aggregation, duplicates and long-lived connections can make endpoint connection telemetry a poor proxy for actual packet/request cadence. Validate against available network/proxy evidence rather than labeling regular intervals as C2.

**Possible DNS abuse:** IR-509 actually calculates first-label Shannon entropy; it is not merely a long-label regex. IR-510 counts name churn under a chosen suffix. IR-511 is only a port-53 destination review. Investigate resolver policy, agent/CDN activity and full event context before escalating.

**Possible tunneling:** Use IR-513/514/517 to find visible command-line arguments, then IR-515/516 for process/listener/connection context. SSH short switches and curl short switches are matched case-sensitively. Configuration-file-only and environment-variable-only behavior may not match. A listener is not proof of Internet exposure, and a process that both listens and connects is not proof of forwarding between those sockets.

## Limits that affect interpretation

Time-bin queries calculate a numeric `WindowStart` from the event timestamp before aggregation. Bins are fixed UTC-aligned 5- or 10-minute intervals, not sliding windows; activity straddling a boundary can fall below a threshold. Counts are observed telemetry events, not packets, sessions, failed attempts or transferred bytes. Distinct counts can be approximate at scale. `collect()` fields are bounded summaries; values collected from different columns are not guaranteed to preserve original row associations.

Correlation queries are static-search hunts. The one-hour bounds require process-start and related activity to be close enough; they intentionally miss activity from much older process starts. Widen both the selected search period and `within` only after assessing query cost. Missing startup/DNS/listener evidence can prevent a match. Correlation on a shared process ID does not establish that a DNS response caused a particular IP connection. IR-516 requires an endpoint identifier because the three-way correlation can be expensive.

Explicit result limits are used to avoid the small default sort output. Sorted event views retain at most the earliest 20,000 matching rows; at that cap, split the search interval. Aggregation, iteration and memory warnings can indicate incomplete results even below the display cap. `limit=max` is not unlimited. The IP exclusion list in IR-511 is not a complete IANA globally routable list and cannot determine which public addresses belong to your organization.

Do not upload exported customer telemetry, credentials, proxy passwords, private IP inventories or investigation indicators to this public repository. Command lines can contain secrets. Only sanitized examples should be used in issues or validation reports.

## Validation and references

[VALIDATION.md](VALIDATION.md) distinguishes local checks from the tenant tests that remain necessary.

Primary references used for syntax and semantics:

- [Field discovery](https://library.humio.com/crowdstrike-query-language/functions-fieldstats.html), [counting](https://library.humio.com/crowdstrike-query-language/functions-count.html), [grouping](https://library.humio.com/crowdstrike-query-language/functions-groupby.html), [math:floor](https://library.humio.com/crowdstrike-query-language/functions-math-floor.html) and [sort limits](https://library.humio.com/crowdstrike-query-language/functions-sort.html).
- [correlate](https://library.humio.com/crowdstrike-query-language/functions-correlate.html), [neighbor](https://library.humio.com/crowdstrike-query-language/functions-neighbor.html), [standard deviation](https://library.humio.com/crowdstrike-query-language/functions-stddev.html), [Shannon entropy](https://library.humio.com/crowdstrike-query-language/functions-shannonentropy.html) and [CIDR matching](https://library.humio.com/crowdstrike-query-language/functions-cidr.html).
- [CrowdStrike process/DNS example](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Combine%20ProcessRollup2%20and%20DnsRequest%20Events.md) and [CrowdStrike native network field example](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Omit%20RFC1819%20CIDR%20Ranges%20from%20Search.md). The latter's filename has a typo; the three private ranges are RFC1918.
- [OpenSSH options](https://man.openbsd.org/ssh), [Microsoft netsh interface / portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) and [curl options](https://curl.se/docs/manpage.html).
