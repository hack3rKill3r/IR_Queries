# CrowdStrike Falcon Incident Response Query Library

CrowdStrike Falcon Advanced Event Search / CQL hunting queries and parser-mapping templates organized for incident response and threat hunting. Validate the required fields and behavior in your tenant before operational use.

## Structure
- IR-001 onward: numbered analyst queries
- One `.cql` file per query
- Category folders for faster navigation

## Important
Falcon field availability can vary by sensor version, platform, event type, parser, and tenant. Validate fields in Falcon's event field browser before standardizing a query for production use.

## Navigation

[Category index](INDEX.md) · [IR-501–520 network/C2/DNS batch](61-Network-C2-DNS/README.md)

The latest batch includes native field discovery, field coverage, scan-pattern candidates, interval analysis, DNS entropy and process-based correlations. Its [validation record](61-Network-C2-DNS/VALIDATION.md) separates local checks from Falcon tenant testing. Earlier queries have not been comprehensively audited as part of this update. A numbered file is not a guarantee of a unique, validated detection.
