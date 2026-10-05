# Specification example SETs

Every example SET claims set printed in these specifications, extracted
verbatim, numbered in order of appearance:

- `ssf-*.json` — OpenID Shared Signals Framework 1.0 Final, §4.1.8, §5,
  §8.1.4 and §8.1.5 (Figures 7–13, 46, 47).
- `caep-*.json` — OpenID CAEP 1.0 Final, §3.
- `risc-*.json` — OpenID RISC 1.0 Final, §2.
- `rfc9967-*.json` — RFC 9967 (SCIM events), §2.3–§2.5, numbered by
  figure. Figure 1 is left out: it elides its "events" claim.

Three deliberate differences from the printed text:

- `risc-fig2-account-disabled.json` is RISC 1.0 §2.3 Figure 2 with the
  trailing comma after `"sub"` removed; as printed it is not valid JSON.
- `rfc9967-fig3-feed-remove.json` is RFC 9967 §2.3.2 Figure 3 with the
  trailing comma after `"externalId"` removed, likewise.
- `ssf-07.json` (SSF §5 Figure 13) keeps its `iat` of 15203800012 — a
  typo for a date in the year 2451. The test decodes every vector with a
  clock set far enough ahead that `iat` is never in the future.
