# Windows logon investigation

**Question.** Which failure threshold is worth taking into a larger pilot?

**Evidence.** The simulated XML export contains 17 rows and arrives in reverse order. One row repeats a record ID on the same host. Sorting and de-duplication leave 16 eligible events. The grouping key is destination host, target domain and account, source IP, and logon type. Three labeled success records have independent simulated case notes.

| Success record | Observation in UTC | Disposition |
| --- | --- | --- |
| 2107 | Failures 2101–2105 run from 09:00 to 09:04. A same-account success from another address at 09:04:59 leaves that sequence open. The matching success arrives at 09:05:00. | Review. The account owner could not identify the source in the case note. |
| 2206 | Five failures start at 10:00. Success at 10:05:01 leaves four inside the five-minute lookback. | Review. The workstation was outside the approved change window. |
| 2303 | Two failures precede a success at 11:01:35. | Close in this exercise. The help-desk ticket confirms typing errors. |

| Minimum failures in five minutes | Review cases surfaced (of two) | Benign cases surfaced (of one) | Missed review records |
| --- | ---: | ---: | --- |
| 5 | 1 | 0 | 2206 |
| 4 | 2 | 0 | None |
| 2 | 2 | 1 | None |

**Decision.** Take four forward for validation on a larger labeled dataset. For record 2107, request source-device ownership and activity following the success. For record 2206, verify the workstation's change history. No case establishes account compromise.

**Limit.** The labels describe the need for follow-up in three simulated cases. This dataset cannot measure a production false-positive rate. Events missing source or account fields are excluded from the rule.

**Replay.** Run `python3 run_portfolio.py` at the project root. Full event IDs and timestamps appear in `evidence/results.json`.

Microsoft documents the success and failure events and their fields. [Success event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) · [Failure event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
