import json
from datetime import datetime,timedelta,timezone
from pathlib import Path
import pytest
from investigation import analyze,parse_events,InputError

def row(seconds=0,user='riya',ip='192.0.2.1',outcome='failure'):
    return {'timestamp':(datetime(2026,9,15,tzinfo=timezone.utc)+timedelta(seconds=seconds)).isoformat(),'user':user,'ip':ip,'outcome':outcome}

def replay(rows):return analyze('\n'.join(json.dumps(r) for r in rows))

def rules(rows):return [a['rule'] for a in replay(rows)['alerts']]

def test_demo_three_rules_and_all_evidence_exists():
    data=analyze(Path('fixtures/demo.jsonl').read_text())
    assert {a['rule'] for a in data['alerts']}=={'burst_success','password_spray','new_ip'}
    ids={e['id'] for e in data['events']}
    assert all(set(a['evidence'])<=ids for a in data['alerts'])
    assert len(data['events'])==15

@pytest.mark.parametrize('times,success,expected', [([0,100,200,300],900,True),([0,100,200,301],302,False),([0,100,200,300],901,False),([0,100,200],201,False),([0,0,0,0],0,False)])
def test_burst_window_boundaries(times,success,expected):
    # Identical events deduplicate: equal time is not four independent failures.
    data=[row(t) for t in times]+[row(success,outcome='success')]
    assert ('burst_success' in rules(data))==expected

def test_equal_timestamp_failure_never_proves_prior_causality():
    rows=[row(t) for t in [0,1,2,3]]+[row(3,outcome='success')]
    assert 'burst_success' not in rules(rows)

@pytest.mark.parametrize('span,users,expected', [(600,4,True),(601,4,False),(300,3,False)])
def test_spray_windows(span,users,expected):
    rows=[row(round(span*i/(users-1)),user='person'+str(i)) for i in range(users)]
    assert ('password_spray' in rules(rows))==expected

def test_spray_segment_single_alert_with_expanded_evidence():
    alerts=replay([row(i*50,user='person'+str(i)) for i in range(6)])['alerts']
    assert len(alerts)==1
    assert len(alerts[0]['evidence'])==6

@pytest.mark.parametrize('baselines,newip,expected', [(2,'192.0.2.2',True),(1,'192.0.2.2',False),(2,'192.0.2.1',False)])
def test_observed_novelty(baselines,newip,expected):
    rows=[row(i,outcome='success') for i in range(baselines)]+[row(5,ip=newip,outcome='success')]
    assert ('new_ip' in rules(rows))==expected

def test_equal_time_does_not_make_baseline():
    assert 'new_ip' not in rules([row(0,ip='192.0.2.1',outcome='success'),row(0,ip='192.0.2.2',outcome='success'),row(0,ip='192.0.2.3',outcome='success')])

def test_order_independence_duplicates_and_fractional_times():
    rows=[row(i) for i in range(4)]+[row(5,outcome='success')]
    a=replay(rows);b=replay(list(reversed(rows))+[rows[0]])
    assert a['events']==b['events'] and a['alerts']==b['alerts']
    assert b['duplicates']==1
    events,_=parse_events('\n'.join(json.dumps(r) for r in [row(.5),row(0)]))
    assert events[0]['timestamp'].endswith('00Z')

@pytest.mark.parametrize('value', [None,'',42,'not-json','{}','{"x":NaN}','{"x":Infinity}','['*2000,'x'*180001,'\n'.join('{}' for _ in range(1001))])
def test_invalid_inputs(value):
    with pytest.raises(InputError):analyze(value)

@pytest.mark.parametrize('key,value', [('timestamp','2026-09-15T00:00:00'),('timestamp','1900-01-01T00:00:00Z'),('timestamp',4),('user','x'*81),('user','bad\nname'),('ip','999.999.999.999'),('ip',42),('outcome','maybe')])
def test_schema_validation(key,value):
    data=row();data[key]=value
    with pytest.raises(InputError) as error:replay([data])
    assert str(value) not in str(error.value)

def test_ipv6_canonicalization():
    data=replay([row(ip='2001:0db8::1'),row(ip='2001:db8:0::1')])
    assert data['event_count']==1 and data['duplicates']==1

def test_quiet_false_positive_fixture():
    rows=[row(0,outcome='success'),row(1),row(2,outcome='success'),row(3,user='dev',ip='192.0.2.2')]
    assert replay(rows)['alerts']==[]
