# Network Security Monitor

A small Python tool for reviewing connection logs and spotting patterns worth investigating.

I wanted a cybersecurity portfolio project with visible evidence: connection events go in, rule matches and a readable report come out. This first version works offline, so it can be demonstrated with synthetic traffic without connecting to a network.

Built with AI assistance as a new portfolio implementation. It is a learning tool, not a production intrusion-detection system.

## Try the demo

Python 3.10 or later. Standard library only; no dependency installation required.

From the repository folder:

```sh
python monitor.py demo/connections.jsonl --output review
```

Open `review/report.html` in a browser. The same alerts are saved in `review/alerts.json`.

The included synthetic demo contains 41 events and produces three alerts: one possible port scan, one sequence of denied connections and one connection burst. An already generated report is available at `demo/review/report.html`.

## What triggers an alert?

| Rule | Default threshold | Grouping |
| --- | --- | --- |
| Possible port scan | 8 distinct destination ports within 60 seconds | Same source and destination IP |
| Repeated denied connections | 5 denied events within 60 seconds | Same source IP |
| Connection burst | 20 events within 60 seconds | Same source IP |

The time window includes events exactly 60 seconds apart. Alerts fire when a threshold is reached and are suppressed while that group stays above the threshold. A rule rearms when a later event for the relevant group causes its window count to fall below the threshold. Different rules can alert on the same events.

Denied events are connection outcomes, not necessarily failed logins. Repeated rows count as separate events; the tool cannot identify duplicate ingestion without event IDs. Port scans across multiple destination IPs are not combined by the scan rule.

## Input format

One JSON object per line:

```json
{"timestamp":"2026-01-01T00:00:00Z","source":"192.0.2.10","destination":"198.51.100.10","port":443,"status":"allowed"}
```

Each event needs a timezone-aware ISO timestamp, valid source and destination IP addresses, an integer port from 1 to 65535 and a status of `allowed` or `denied`. IPv4 and IPv6 addresses are accepted. Events are sorted and converted to UTC before analysis. Invalid rows stop the run with their line number. Blank lines are ignored.

The demo addresses are examples and the events are synthetic. To use a real firewall export, first transform it into this schema. This version does not include vendor-specific parsers or infer connection outcomes from raw packets.

## Change thresholds

```sh
python monitor.py demo/connections.jsonl --window 120 --scan-ports 6 --denied-count 4 --burst-count 30 --output review
```

All window and threshold values must be positive integers. Thresholds are heuristics; legitimate activity can trigger them.

## Check the behaviour

```sh
python verify_monitor.py
```

Five tests cover distinct-port counting, destination isolation, denied-event filtering, connection bursts, window boundaries, alert suppression and rearming, input ordering, invalid events and report output.

## Files

- `monitor.py`: parser, sliding-window rules, CLI and report writer
- `verify_monitor.py`: behavioural checks
- `demo/connections.jsonl`: synthetic connection events
- `demo/review/`: generated HTML and JSON for the demo

## What I would improve next

A next version could add log adapters, event IDs, cross-destination scan detection and labelled datasets for measuring false-positive rates. The current program loads the entire file and retains per-source bookkeeping, so very large logs need a streaming design.

No live packet capture, network scanning, blocking or authentication monitoring is implemented. A rule match provides a reason to investigate; it does not establish an attack.
