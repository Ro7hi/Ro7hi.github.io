# Wi-Fi inventory and security settings

**Question.** Which observations still need attention after the network owner approves a new access point?

**Evidence.** Eight simulated observations come from a connected client. LAB-NET is the covered network. The initial inventory includes radios ending in 01 and 02. Change CHG-17 adds only radio 03. Both policies permit the same authentication/cipher pair, WPA2-Personal with CCMP.

| UTC | Observation | Decision after CHG-17 |
| --- | --- | --- |
| 12:00 and 12:01 | Client uses radios 01 then 02 with the approved mode. | Expected roaming. |
| 12:02 | Client uses newly approved radio 03 with the approved mode. | Close the inventory finding. |
| 12:03 | Radio 09 is unlisted and the observed mode is Open/None. | Review both deviations in one observation. |
| 12:04 | Radio 01 is listed and the observed mode is Open/None. | Review the mode against the approved router configuration. |
| 12:05 and 12:07 | One observation lacks a cipher and one lacks a BSSID. | Collect the missing evidence. |
| 12:06 | Client reports VISITOR. | Exclude from the LAB-NET decision. |

**Result.** Three observations had a documented deviation before the inventory update. Two remained afterward. Two readings had incomplete telemetry and one belonged to another SSID. Review the approved equipment record and repeat the two questionable observations from a second trusted source before attributing a cause.

**Limit.** A BSSID is the observed radio identifier. Matching an inventory entry alone cannot authenticate the equipment. Findings here are observations in a simulated review, not attacks.

**Replay.** Run `python3 run_portfolio.py`. The per-reading evidence is in `evidence/results.json`, including missing fields and multiple deviations on a single reading.

The Windows WLAN command reference documents how to view your own connected interface. [Microsoft WLAN commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
