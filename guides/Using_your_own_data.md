## 1. Windows logon investigation

**Interview question.** An account had repeated failed network sign-ins, then a successful sign-in. Which records belong together? What would you check before escalating?

The script reads a saved Security event log in XML. It uses the target domain and account, destination host, source IP and logon type to group events. It sorts them by time and flags a successful logon (4624) preceded by at least five failures (4625) within the previous five minutes for that group. It covers network and remote interactive logons with populated identifying fields. Each success closes its sequence. The output shows the source event record IDs so a reviewer can reproduce the finding.

**Demo.** Run the default, then lower the threshold.

```powershell
py -3 01_windows_logon_triage/triage.py --threshold 2
```

The default flags one sequence ending at record 110. Record 107 is a successful sign-in to the same account from a different source and stays outside that sequence. The lower threshold also flags record 105. In this fictional case, the user for record 105 confirmed two typing errors. The case ending at 110 is unexplained. A useful next check is whether the account owner recognizes that source and time. The pattern on its own leaves the cause unresolved.

**Make it yours.** Export an existing Windows Security log sample from your own test machine as XML. In Event Viewer, select Windows Logs → Security, filter on 4624 and 4625, and save the filtered log as XML. Supply the path as the first argument to the script. An export may contain zero eligible network logons. Local console logons and events lacking source details fall outside this rule. Alternatively, add a new labeled edge case to the fictional export and document why the rule should include or exclude it.

**Evidence to keep.** Save the two threshold outputs. Write a one-page incident note with the observed timeline, exact record IDs, plausible explanations, the next evidence you would request and a reason for choosing your threshold. Use anonymized records in any public demo.

Microsoft's event field references are available for [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) and [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).

## 2. Dependency remediation for a Flask chatbot

**Interview question.** A dependency audit showed three advisories yesterday and one today. What evidence would let you call a finding fixed?

The script compares two pip-audit JSON reports. It tracks package names, versions, advisory IDs and coverage changes. The fixture uses fictional package names and advisory IDs. In the sample, DEMO-001 disappears after a version change, DEMO-002 persists, and the second audit skips the package that had DEMO-003. The last item requires follow-up. A skipped package gives you no evidence of remediation.

**Make it yours.** Work in a separate copy or branch of your own chatbot and record the Python version. Use a disposable compatible environment and your project's dependency file. Install pip-audit in a compatible tooling environment following the project documentation. The real audit requires internet access. The commands below assume the chatbot requirements file, audit tool and paths are available from the current directory.

```text
pip-audit -r requirements.txt --format json --output before.json
```

Read one advisory, identify whether the affected package is direct or transitive, and select a compatible change. Apply it on the branch. Run a chatbot smoke test using a fictional message. Record the expected and actual HTTP status and response shape. Then use the same audit settings for the second run.

```text
pip-audit -r requirements.txt --format json --output after.json
```

From the starter folder, pass the paths to those two real reports.

```powershell
py -3 02_chatbot_dependency_review/compare_audits.py path/to/before.json path/to/after.json
```

Use the same advisory service and record audit times. The comparison matches IDs and supplied aliases within each package. Feed changes or missing alias information still affect the comparison. If the project has zero findings, record the inventory and coverage, and demonstrate the remediation example separately with the fictional reports. If dependency resolution fails, record the error and resolve the environment issue before interpreting counts.

**Evidence to keep.** The dependency change, dated audit results, a short decision log, and the same application test before and after the change. Include a sentence about what you would roll back if the change broke chatbot responses. Use only synthetic messages in screenshots.

See [PyPA's pip-audit documentation](https://github.com/pypa/pip-audit).

## 3. Wi-Fi security baseline review

**Interview question.** Your laptop connects to the usual network name through a different radio. How do you distinguish routine roaming, a newly approved access point and an unexpected connection setting?

The SSID is the network name. The BSSID identifies the radio connection recorded by the client. Your inventory lists approved BSSIDs and authentication/cipher pairs for each covered SSID. The script reviews a CSV of connected-client observations. Its two checks answer different questions: whether the radio is listed and whether the connection used an approved security mode.

**Demo.** The initial inventory contains two BSSIDs for LAB-NET, so roaming between those two is expected. The sample flags an unlisted third radio and a separate Open/None observation. A fifth observation is for an SSID outside the policy. In this fictional change record, the network owner confirmed that a new access point with BSSID 02:00:00:00:00:03 was installed. Rerun using the approved inventory.

```powershell
py -3 03_wifi_baseline_review/review_wifi.py --policy 03_wifi_baseline_review/approved_change.json
```

Two observations are flagged before the inventory update and one after. The unexpected security mode still needs review. A BSSID match alone cannot establish an access point's identity.

**Make it yours.** Build an inventory for a router you own or administer using its settings or equipment records. Use `netsh wlan show interfaces` on your connected Windows laptop to read the current SSID, BSSID, authentication and cipher, where available. Record the timestamp with its time zone. Use the same labels in the inventory and CSV. If you have only one radio, record its normal connection, then use the supplied sample to illustrate the other cases. Keep real device identifiers private and pseudonymize both sides consistently for the portfolio.

**Evidence to keep.** The approved inventory, a few timestamped observations, before and after reports, and a change note explaining which evidence justified updating the inventory. Show an interviewer why the unexpected mode still appears.

See [Microsoft's WLAN command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan).

