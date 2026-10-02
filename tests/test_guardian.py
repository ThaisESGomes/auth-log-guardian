import unittest
from guardian import analyze, parse, markdown


def row(second, result='Failed', user='admin', ip='192.0.2.10'):
    return f'2026-10-01T12:{second // 60:02}:{second % 60:02}Z lab sshd[1]: {result} password for {user} from {ip} port 1234 ssh2'


class DetectionTests(unittest.TestCase):
    def test_threshold_and_success(self):
        result = analyze([row(i * 10) for i in range(5)] + [row(50, 'Accepted')])
        self.assertEqual([a['rule'] for a in result['alerts']], ['repeated_failures', 'success_after_failures'])
        self.assertEqual(result['alerts'][1]['evidence_lines'], [1, 2, 3, 4, 5])

    def test_legitimate_typo(self):
        self.assertEqual(analyze([row(0), row(1, 'Accepted')])['alerts'], [])

    def test_window_expiration(self):
        self.assertEqual(analyze([row(i * 50) for i in range(5)])['alerts'], [])

    def test_window_boundary(self):
        self.assertEqual(len(analyze([row(0), row(120)], threshold=2)['alerts']), 1)
        self.assertEqual(analyze([row(0), row(121)], threshold=2)['alerts'], [])

    def test_other_user_success_not_correlated(self):
        result = analyze([row(i) for i in range(5)] + [row(6, 'Accepted', 'other')])
        self.assertEqual(len(result['alerts']), 1)

    def test_allowlist_ipv6(self):
        result = analyze([row(i, ip='2001:db8::1') for i in range(5)], allowlist=['2001:db8::/32'])
        self.assertEqual(result['alerts'], [])
        self.assertEqual(result['summary']['allowlisted_events'], 5)

    def test_invalid_lines(self):
        result = analyze(['garbage', row(1, ip='999.1.1.1')])
        self.assertEqual(result['summary']['ignored_lines'], 2)

    def test_syslog(self):
        event = parse('Oct  1 12:00:00 lab sshd[1]: Failed password for invalid user root from ::1 port 22 ssh2', 1, 2026)
        self.assertEqual(event.user, 'root')
        self.assertEqual(event.time.year, 2026)

    def test_out_of_order(self):
        self.assertEqual(len(analyze([row(i) for i in reversed(range(5))])['alerts']), 1)

    def test_no_duplicate_alerts_in_burst(self):
        self.assertEqual(len(analyze([row(i) for i in range(20)])['alerts']), 1)

    def test_markdown_escapes_user(self):
        report = analyze([row(i, user='<script>|x') for i in range(5)])
        self.assertNotIn('<script>', markdown(report))
        self.assertIn('&#124;', markdown(report))

    def test_invalid_settings(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=0)


if __name__ == '__main__':
    unittest.main()
