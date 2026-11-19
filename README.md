# Rohit Amadala | Cybersecurity placement portfolio

I’m a final-year Electronics and Communication Engineering student at SRM Institute of Science and Technology (SRMIST), preparing for CompTIA Security+ and looking for an entry-level cybersecurity engineering or SOC analyst role in India. My ECE coursework sparked my interest in wireless security. This portfolio explores how an analyst decides which alerts need a closer look.

[Four-page casebook](Rohit_Cybersecurity_Casebook.pdf) · [72-second narrated walkthrough](Cybersecurity_Lab_Walkthrough.mp4) · [English captions](placement/Walkthrough_en.srt)

## Three investigations

| Lab | Question | Result on the supplied data |
| --- | --- | --- |
| [Windows logon triage](01_windows_logon_triage/CASE.md) | How many failures before a successful sign-in should trigger review? | Across 17 simulated records, a threshold of four failures in five minutes found both cases labeled for review and excluded a confirmed typing error. A threshold of five missed one case by a second. |
| [Chatbot dependency review](02_chatbot_dependency_review/CASE.md) | Which findings are still open after a second dependency audit? | Across two four-package snapshots, one advisory persisted under a different identifier. A skipped package still needed follow-up. |
| [Wi-Fi security baseline review](03_wifi_baseline_review/CASE.md) | Which connection settings still need investigation after an approved access-point change? | Of eight observations, three were flagged before the inventory update and two afterward. One approved radio still reported an open connection. |

The cases use synthetic logs, audit reports and Wi-Fi observations. The dependency lab includes a separate local check of a Jinja2 reference template. The code, case notes, visuals and narration were prepared with AI assistance.

## Reproduce the findings

Clone or download this repository, then open a terminal in the folder containing `run_portfolio.py`. The replay and 19 automated tests use Python 3.8 or later and its standard library.

**Windows**

```powershell
py -3 run_portfolio.py
py -3 -m unittest discover -s tests -v
```

**Linux or macOS**

```sh
python3 run_portfolio.py
python3 -m unittest discover -s tests -v
```

Add `--json-out my_results.json` to the replay command to save a new report. Compare it with the [reference JSON](evidence/results.json) or review the [console output](evidence/replay.txt) and [test results](evidence/test_results.txt).

The optional renderer check uses a Python environment with Jinja2 installed. Run `python3 02_chatbot_dependency_review/check_renderer.py` (or `py -3` on Windows). The [recorded component check](evidence/renderer.json) includes the Jinja2 version, three inputs and their expected and observed outputs.

## Explore the evidence

Each case report links the result to a decision and explains what additional evidence an analyst would request. The [input guide](guides/Using_your_own_data.md) explains how to run the scripts on your own exported records. The project folders also include small introductory samples and their expected output.

[GitHub](https://github.com/Ro7hi) · [LinkedIn](https://www.linkedin.com/in/rohit-amadala-a12056318/)
