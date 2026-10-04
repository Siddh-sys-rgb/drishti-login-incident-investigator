"""Deterministic offline authentication-event replay and explainable rules."""
import hashlib
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timezone

MAX_BYTES = 180_000
MAX_EVENTS = 1000
RULES = {
    'burst_success': {'label': 'Failure burst followed by success', 'note': 'Four failures for one account/IP within 5 minutes, then success within 10 minutes. Mistyped credentials or helpdesk work can explain this.'},
    'password_spray': {'label': 'One IP, multiple failing accounts', 'note': 'Failures for four distinct accounts from one IP within 10 minutes. Shared office networks can explain this.'},
    'new_ip': {'label': 'New IP after observed baseline', 'note': 'Success from a new IP after at least two earlier successes for that account. Mobile networks, VPNs and travel can explain this. Novelty is only within this uploaded dataset.'},
}
class InputError(ValueError):
    pass

def parse_events(text):
    if not isinstance(text, str) or not text.strip():
        raise InputError('Provide authentication events as JSONL.')
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise InputError('Upload exceeds 180 KB.')
    seen = {}; duplicate_count = 0
    rows = [line for line in text.splitlines() if line.strip()]
    if len(rows) > MAX_EVENTS:
        raise InputError('Use at most 1,000 events.')
    for index, line in enumerate(rows, 1):
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError()
            if set(row) != {'timestamp', 'user', 'ip', 'outcome'}:
                raise ValueError()
            user = row['user']
            if not isinstance(user, str) or not 1 <= len(user) <= 80 or any(ord(c) < 32 for c in user):
                raise ValueError()
            if not isinstance(row['timestamp'], str) or len(row['timestamp']) > 40:
                raise ValueError()
            dt = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
            if dt.tzinfo is None:
                raise ValueError()
            dt = dt.astimezone(timezone.utc)
            if not 2000 <= dt.year <= 2100:
                raise ValueError()
            if not isinstance(row['ip'], str) or len(row['ip']) > 45:
                raise ValueError()
            ip = str(ipaddress.ip_address(row['ip']))
            if row['outcome'] not in ('success', 'failure'):
                raise ValueError()
            normalized = {'timestamp': dt.isoformat().replace('+00:00', 'Z'), 'user': user, 'ip': ip, 'outcome': row['outcome']}
            event_id = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()[:20]
            event = dict(normalized, id=event_id)
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise InputError(f'Invalid event on non-empty line {index}; use the documented four-field schema.') from None
        if event_id in seen:
            duplicate_count += 1
        else:
            seen[event_id] = event
    return sorted(seen.values(), key=lambda e: (datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')), e['id'])), duplicate_count

def analyze(text):
    events, duplicates = parse_events(text)
    alerts = {}; failure_pairs = defaultdict(list); ip_failures = defaultdict(list); prior_success = defaultdict(list)
    def seconds(e):
        return datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')).timestamp()
    def add(rule, evidence, subject, end):
        ids = sorted(e['id'] for e in evidence)
        aid = hashlib.sha256(json.dumps([rule, ids]).encode()).hexdigest()[:20]
        alerts[aid] = {'id': aid, 'rule': rule, 'label': RULES[rule]['label'], 'note': RULES[rule]['note'], 'subject': subject, 'timestamp': end['timestamp'], 'evidence': ids, 'status': 'open', 'revision': 0, 'annotation': '', 'investigator': ''}
    for e in events:
        t = seconds(e); pair = (e['user'], e['ip'])
        if e['outcome'] == 'failure':
            failure_pairs[pair].append(e)
            current = [x for x in ip_failures[e['ip']] if 0 <= t - seconds(x) <= 600] + [e]
            ip_failures[e['ip']] = current
            if len({x['user'] for x in current}) >= 4:
                # One alert per contiguous spray segment, expanded with its full evidence.
                previous = [k for k, a in alerts.items() if a['rule'] == 'password_spray' and a['subject'] == e['ip'] and set(a['evidence']).intersection(x['id'] for x in current)]
                for k in previous:
                    del alerts[k]
                add('password_spray', current, e['ip'], e)
        else:
            failures = [x for x in failure_pairs[pair] if 0 <= t - seconds(x) <= 900]
            burst = []
            for last in reversed(failures):
                candidates = [x for x in failures if 0 <= seconds(last) - seconds(x) <= 300]
                if len(candidates) >= 4 and t - seconds(last) <= 600:
                    burst = candidates; break
            if burst:
                add('burst_success', burst + [e], e['user'] + ' / ' + e['ip'], e)
            baseline = [x for x in prior_success[e['user']] if seconds(x) < t]
            if len(baseline) >= 2 and e['ip'] not in {x['ip'] for x in baseline}:
                add('new_ip', baseline[-2:] + [e], e['user'], e)
            prior_success[e['user']].append(e)
    return {'events': events, 'alerts': sorted(alerts.values(), key=lambda a: (datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00')), a['id'])), 'duplicates': duplicates, 'input_events': len(events) + duplicates, 'event_count': len(events)}
