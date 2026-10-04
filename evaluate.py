"""Evaluate rule firing and benign explanations on a small authored replay corpus."""
import json
from datetime import datetime,timedelta,timezone
from investigation import analyze

def event(second,user='riya',ip='192.0.2.1',outcome='failure'):
    return dict(timestamp=(datetime(2026,9,15,tzinfo=timezone.utc)+timedelta(seconds=second)).isoformat(),user=user,ip=ip,outcome=outcome)

def corpus():
    return [
      dict(name='failure_burst_then_success',events=[event(i*30) for i in range(4)]+[event(150,outcome='success')],expected=['burst_success'],adjudication='needs_review'),
      dict(name='shared_office_network',events=[event(i*30,user='person'+str(i)) for i in range(4)],expected=['password_spray'],adjudication='expected_activity'),
      dict(name='mobile_network_change',events=[event(0,outcome='success'),event(30,outcome='success'),event(60,ip='192.0.2.2',outcome='success')],expected=['new_ip'],adjudication='expected_activity'),
      dict(name='ordinary_typo_then_success',events=[event(0),event(30,outcome='success')],expected=[],adjudication='expected_activity'),
      dict(name='quiet_activity',events=[event(0,outcome='success'),event(60,outcome='success')],expected=[],adjudication='expected_activity'),
      dict(name='failure_burst_outside_window',events=[event(i*110) for i in range(4)]+[event(340,outcome='success')],expected=[],adjudication='needs_review'),
    ]

def evaluate():
    results=[]
    for case in corpus():
        result=analyze('\n'.join(json.dumps(e) for e in case['events']))
        fired=sorted({a['rule'] for a in result['alerts']})
        results.append(dict(name=case['name'],expected=case['expected'],fired=fired,matched=fired==case['expected'],adjudication=case['adjudication']))
    return dict(scenarios=len(results),matched=sum(c['matched'] for c in results),benign_scenarios_with_signals=sum(c['adjudication']=='expected_activity' and bool(c['fired']) for c in results),cases=results,note='Rule agreement is not account-compromise precision. Benign explanations deliberately trigger two patterns.')

if __name__=='__main__':print(json.dumps(evaluate(),indent=2))
