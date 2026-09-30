from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from monitor import analyse, load_events, write_report


def event(second, port=443, status='allowed', source='192.0.2.1', destination='198.51.100.1'):
    return {'timestamp': datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second), 'source': source, 'destination': destination, 'port': port, 'status': status}


class DetectionChecks(unittest.TestCase):
    def test_scan_distinct_ports_and_destinations(self):
        self.assertEqual(analyse([event(i) for i in range(8)]), [])
        alerts = analyse([event(i, 1000 + i) for i in range(8)])
        self.assertEqual([a['rule'] for a in alerts], ['port_scan'])
        events = [event(i, 1000 + i, destination=f'198.51.100.{i+1}') for i in range(8)]
        self.assertEqual(analyse(events), [])

    def test_denials_and_burst(self):
        self.assertEqual(analyse([event(i, status='allowed') for i in range(5)]), [])
        self.assertEqual(analyse([event(i, status='denied') for i in range(5)])[0]['rule'], 'repeated_denials')
        self.assertEqual(analyse([event(i) for i in range(20)])[0]['rule'], 'connection_burst')

    def test_window_boundary_and_rearming(self):
        alerts = analyse([event(0, 80), event(60, 443)], scan_ports=2)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(analyse([event(0, 80), event(61, 443)], scan_ports=2), [])
        events = [event(0, 80), event(1, 443), event(2, 22), event(100, 80), event(101, 443)]
        self.assertEqual(len(analyse(events, scan_ports=2)), 2)

    def test_sorted_input_and_empty_data(self):
        events = [event(1, 443), event(0, 80)]
        self.assertEqual(analyse(events, scan_ports=2), analyse(events[::-1], scan_ports=2))
        self.assertEqual(analyse([]), [])

    def test_validation_and_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'events.jsonl'
            good = {'timestamp': '2026-01-01T00:00:00Z', 'source': '192.0.2.1', 'destination': '198.51.100.1', 'port': 443, 'status': 'allowed'}
            path.write_text(json.dumps(good))
            events = load_events(path)
            write_report(events, [], Path(folder) / 'output')
            self.assertIn('No thresholds were reached', (Path(folder) / 'output/report.html').read_text())
            self.assertEqual(json.loads((Path(folder) / 'output/alerts.json').read_text())['events'], 1)
            for field, value in [('timestamp', '2026-01-01T00:00:00'), ('source', 'invalid'), ('port', True), ('port', 0), ('status', 'other')]:
                path.write_text(json.dumps({**good, field: value}))
                with self.assertRaises(ValueError):
                    load_events(path)


if __name__ == '__main__':
    unittest.main()
