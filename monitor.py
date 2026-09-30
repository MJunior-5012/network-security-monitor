import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import html
import ipaddress
import json
from pathlib import Path


def load_events(path):
    events = []
    with Path(path).open(encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                if timestamp.tzinfo is None:
                    raise ValueError('Timestamp requires a timezone')
                source = str(ipaddress.ip_address(event['source']))
                destination = str(ipaddress.ip_address(event['destination']))
                port = event['port']
                if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                    raise ValueError('Port must be an integer from 1 to 65535')
                status = event['status']
                if status not in ('allowed', 'denied'):
                    raise ValueError('Status must be allowed or denied')
                events.append({'timestamp': timestamp.astimezone(timezone.utc), 'source': source, 'destination': destination, 'port': port, 'status': status})
            except (ValueError, KeyError, TypeError, AttributeError) as error:
                raise ValueError(f'Invalid event on line {line_number}: {error}') from error
    return sorted(events, key=lambda event: event['timestamp'])


def analyse(events, window=60, scan_ports=8, denied_count=5, burst_count=20):
    if min(window, scan_ports, denied_count, burst_count) < 1:
        raise ValueError('Window and thresholds must be positive')
    scans = defaultdict(deque)
    denials = defaultdict(deque)
    bursts = defaultdict(deque)
    active = set()
    alerts = []
    for event in sorted(events, key=lambda item: item['timestamp']):
        source, destination, time = event['source'], event['destination'], event['timestamp']
        pair = source, destination
        scans[pair].append(event)
        bursts[source].append(event)
        if event['status'] == 'denied':
            denials[source].append(event)
        groups = [('port_scan', pair, scans[pair], scan_ports), ('repeated_denials', source, denials[source], denied_count), ('connection_burst', source, bursts[source], burst_count)]
        for rule, key, queue, threshold in groups:
            while queue and (time - queue[0]['timestamp']).total_seconds() > window:
                queue.popleft()
            count = len({item['port'] for item in queue}) if rule == 'port_scan' else len(queue)
            identity = rule, key
            if count < threshold:
                active.discard(identity)
                continue
            if identity in active:
                continue
            active.add(identity)
            alerts.append({
                'rule': rule,
                'timestamp': time.isoformat(),
                'source': source,
                'destination': destination if rule == 'port_scan' else None,
                'observed': count,
                'threshold': threshold,
                'window_seconds': window,
                'evidence_start': queue[0]['timestamp'].isoformat(),
                'ports': sorted({item['port'] for item in queue}),
            })
    return alerts


def write_report(events, alerts, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    summary = {'events': len(events), 'sources': len({event['source'] for event in events}), 'alerts': alerts}
    (output / 'alerts.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    rows = []
    for alert in alerts:
        values = [alert['timestamp'], alert['rule'].replace('_', ' '), alert['source'], alert['destination'] or 'Multiple or unspecified', str(alert['observed']), str(alert['threshold'])]
        rows.append('<tr>' + ''.join('<td>' + html.escape(value) + '</td>' for value in values) + '</tr>')
    table = '<table><thead><tr><th>Time (UTC)</th><th>Rule</th><th>Source</th><th>Destination</th><th>Observed</th><th>Threshold</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table>' if rows else '<p>No thresholds were reached.</p>'
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connection review</title><style>body{font-family:system-ui,sans-serif;background:#f3f6fa;color:#183047;margin:40px auto;padding:0 24px;max-width:1100px}h1{font-size:36px;margin-bottom:8px}.summary{display:flex;gap:24px;margin:24px 0}.card{background:white;padding:20px;border-radius:10px;flex:1}.card strong{font-size:30px;display:block}table{border-collapse:collapse;background:white;width:100%;font-size:14px}th,td{text-align:left;padding:14px;border-bottom:1px solid #dbe3ed}th{background:#183047;color:white}.scroll{overflow:auto}footer{margin-top:24px;color:#52677a}</style><h1>Connection review</h1><p>Offline event analysis · evidence for investigation</p>'''
    page += f'<div class="summary"><div class="card"><strong>{len(events)}</strong>Events</div><div class="card"><strong>{summary["sources"]}</strong>Sources</div><div class="card"><strong>{len(alerts)}</strong>Alerts</div></div><div class="scroll">{table}</div><footer>Rule matches indicate activity worth reviewing. They do not establish an attack. No live capture or blocking is performed.</footer></html>'
    (output / 'report.html').write_text(page, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Analyse connection events from a JSONL file')
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path, default=Path('review'))
    parser.add_argument('--window', type=int, default=60)
    parser.add_argument('--scan-ports', type=int, default=8)
    parser.add_argument('--denied-count', type=int, default=5)
    parser.add_argument('--burst-count', type=int, default=20)
    args = parser.parse_args()
    try:
        events = load_events(args.input)
        alerts = analyse(events, args.window, args.scan_ports, args.denied_count, args.burst_count)
        write_report(events, alerts, args.output)
    except (ValueError, OSError) as error:
        parser.exit(2, f'Error: {error}\n')
    print(f'{len(events)} events, {len(alerts)} alerts')
    print(f'Report: {args.output / "report.html"}')


if __name__ == '__main__':
    main()
