"""Offline OpenSSH authentication log analyzer. Python 3.11+, standard library only."""
from __future__ import annotations
import argparse
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import ipaddress
import json
from pathlib import Path
import re
import sys
import tomllib

AUTH = re.compile(r'\b(?P<result>Failed|Accepted) (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+')
STAMP = re.compile(r'^(\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s')

@dataclass(frozen=True)
class Event:
    time: datetime
    result: str
    user: str
    ip: str
    line: int


def parse(line: str, number: int, year: int) -> Event | None:
    """Parse OpenSSH Failed/Accepted messages; timestamps without zone mean UTC."""
    match, stamp = AUTH.search(line), STAMP.match(line)
    if not match or not stamp:
        return None
    try:
        ip = str(ipaddress.ip_address(match['ip']))
        value = stamp[1]
        time = (datetime.fromisoformat(value.replace('Z', '+00:00')) if value[0].isdigit()
                else datetime.strptime(f'{year} {value}', '%Y %b %d %H:%M:%S'))
        if time.tzinfo is None:
            time = time.replace(tzinfo=timezone.utc)
        return Event(time.astimezone(timezone.utc), match['result'], match['user'], ip, number)
    except ValueError:
        return None


def analyze(lines, *, threshold=5, window_seconds=120, year=2026, allowlist=()):
    if threshold < 2 or window_seconds < 1:
        raise ValueError('threshold deve ser >= 2 e window_seconds >= 1')
    networks = [ipaddress.ip_network(item) for item in allowlist]
    events, ignored = [], 0
    for number, line in enumerate(lines, 1):
        event = parse(line, number, year)
        if event is None:
            ignored += 1
        else:
            events.append(event)
    events.sort(key=lambda event: (event.time, event.line))
    pending = defaultdict(deque)
    flagged = set()
    alerts = []
    excluded = 0
    for event in events:
        address = ipaddress.ip_address(event.ip)
        if any(address in network for network in networks):
            excluded += 1
            continue
        failures = pending[event.ip]
        cutoff = event.time - timedelta(seconds=window_seconds)
        while failures and failures[0].time < cutoff:
            failures.popleft()
        if len(failures) < threshold:
            flagged.discard(event.ip)
        if event.result == 'Failed':
            failures.append(event)
            if len(failures) >= threshold and event.ip not in flagged:
                alerts.append(alert('repeated_failures', event, list(failures)))
                flagged.add(event.ip)
        else:
            same_user = [failure for failure in failures if failure.user == event.user]
            if len(same_user) >= threshold:
                alerts.append(alert('success_after_failures', event, same_user))
            # A success closes only this user's sequence, not other users on the IP.
            pending[event.ip] = deque(failure for failure in failures if failure.user != event.user)
            if len(pending[event.ip]) < threshold:
                flagged.discard(event.ip)
    return {'summary': {'parsed_events': len(events), 'ignored_lines': ignored,
                        'allowlisted_events': excluded, 'alerts': len(alerts)},
            'settings': {'threshold': threshold, 'window_seconds': window_seconds, 'year': year},
            'alerts': alerts}


def alert(kind, event, failures):
    return {'rule': kind, 'severity': 'high' if kind == 'success_after_failures' else 'medium',
            'ip': event.ip, 'user': event.user, 'time': event.time.isoformat(),
            'failure_count': len(failures), 'evidence_lines': [failure.line for failure in failures],
            'trigger_line': event.line,
            'reason': ('Login aceito após falhas para o mesmo usuário e IP.' if kind == 'success_after_failures'
                       else 'Limite de falhas por IP atingido dentro da janela.')}


def markdown(report):
    rows = ['# Relatório Auth Log Guardian', '',
            f"Eventos analisados: {report['summary']['parsed_events']} | Alertas: {report['summary']['alerts']}", '',
            '| Regra | IP | Usuário | Falhas | Linhas de evidência |',
            '|---|---|---|---:|---|']
    def escape(value):
        return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('`', '&#96;')
    for item in report['alerts']:
        rows.append('| ' + ' | '.join(escape(item[key]) for key in
                    ('rule', 'ip', 'user', 'failure_count', 'evidence_lines')) + ' |')
    return '\n'.join(rows) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--year', type=int, default=2026, help='Ano explícito para syslog sem ano')
    parser.add_argument('--format', choices=['json', 'markdown'], default='json')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        config = tomllib.loads(args.config.read_text()) if args.config else {}
        unknown = set(config) - {'threshold', 'window_seconds', 'allowlist'}
        if unknown:
            raise ValueError(f'Configurações desconhecidas: {sorted(unknown)}')
        threshold, window = config.get('threshold', 5), config.get('window_seconds', 120)
        if type(threshold) is not int or type(window) is not int:
            raise ValueError('threshold e window_seconds devem ser inteiros')
        allowlist = config.get('allowlist', [])
        if not isinstance(allowlist, list) or not all(isinstance(item, str) for item in allowlist):
            raise ValueError('allowlist deve ser uma lista de IPs ou redes em texto')
        with args.log.open(encoding='utf-8', errors='replace') as source:
            report = analyze(source, threshold=threshold, window_seconds=window,
                             year=args.year, allowlist=allowlist)
        result = markdown(report) if args.format == 'markdown' else json.dumps(report, indent=2, ensure_ascii=False) + '\n'
        if args.output:
            args.output.write_text(result, encoding='utf-8')
        else:
            print(result, end='')
    except (OSError, ValueError, TypeError) as error:
        parser.exit(2, f'Erro: {error}\n')


if __name__ == '__main__':
    main()
