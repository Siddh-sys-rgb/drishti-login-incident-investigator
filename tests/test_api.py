import io,json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
from app import create_app
import storage

def demo_run(client,csrf):
    return client.post('/api/runs',json=client.get('/api/demo').json,headers=csrf).json

def review_data(revision=0):
    return dict(status='expected',annotation='Shared office network; validate with Riya.',investigator='Meera Desai',revision=revision)

def test_health_home_cookie_headers(client):
    assert client.get('/').status_code==200
    assert client.get('/api/health').json['app']=='Drishti'
    response=client.get('/api/bootstrap')
    assert 'drishti_session=' in response.headers['Set-Cookie']
    assert 'HttpOnly' in response.headers['Set-Cookie']
    assert response.headers['Cache-Control']=='no-store'

def test_csrf_host_origin_guards(client,csrf):
    assert client.post('/api/runs',json={}).status_code==403
    assert client.get('/api/health',headers={'Host':'bad.test'}).status_code==400
    assert client.post('/api/runs',json={},headers={**csrf,'Origin':'http://bad.test'}).status_code==403

def test_replay_order_and_reupload_preserves_reviews(client,csrf):
    run=demo_run(client,csrf);aid=run['alerts'][0]['id'];url='/api/runs/'+run['id']+'/alerts/'+aid
    changed=client.patch(url,json=review_data(),headers=csrf)
    assert changed.status_code==200
    reversed_text='\n'.join(reversed(client.get('/api/demo').json['text'].splitlines()))
    repeat=client.post('/api/runs',json={'text':reversed_text},headers=csrf).json
    assert repeat['id']==run['id']
    assert next(a for a in repeat['alerts'] if a['id']==aid)['revision']==1
    assert len(client.get('/api/runs').json['runs'])==1
    assert client.patch(url,json=review_data(),headers=csrf).status_code==409
    assert len(client.get('/api/runs/'+run['id']+'/audit').json['audit'])==1

def test_concurrent_annotation_one_winner(application,client,csrf):
    run=demo_run(client,csrf);aid=run['alerts'][0]['id']
    def update():
        try:storage.annotate(application.config['DB'],run['id'],aid,review_data());return 'saved'
        except storage.Conflict:return 'conflict'
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:update(),range(2)))
    assert sorted(results)==['conflict','saved']
    assert len(storage.audit(application.config['DB'],run['id']))==1

@pytest.mark.parametrize('patch', [ {'status':'compromised'},{'revision':True},{'revision':-1},{'annotation':'x'*801},{'investigator':''},{'investigator':'bad\nname'}])
def test_bad_review_data(client,csrf,patch):
    run=demo_run(client,csrf);data=review_data();data.update(patch)
    assert client.patch('/api/runs/'+run['id']+'/alerts/'+run['alerts'][0]['id'],json=data,headers=csrf).status_code==400

def test_upload_export_and_evidence(client,csrf):
    text=client.get('/api/demo').json['text']
    response=client.post('/api/runs',data={'file':(io.BytesIO(text.encode()),'demo.jsonl')},headers=csrf)
    assert response.status_code==201
    exported=client.get('/api/runs/'+response.json['id']+'/export')
    assert exported.mimetype=='application/octet-stream'
    assert 'attachment' in exported.headers['Content-Disposition']
    assert len(json.loads(exported.data)['events'])==15

@pytest.mark.parametrize('payload',[[],{}, {'text':'{broken secret=LEAK_SENTINEL'}])
def test_safe_validation_errors(client,csrf,payload):
    response=client.post('/api/runs',json=payload,headers=csrf)
    assert response.status_code==400
    assert b'LEAK_SENTINEL' not in response.data

def test_upload_utf8_and_size(client,csrf):
    assert client.post('/api/runs',data={'file':(io.BytesIO(b'\xff'),'bad.jsonl')},headers=csrf).status_code==400
    assert client.post('/api/runs',data='x'*500000,content_type='application/json',headers=csrf).status_code==413

def test_no_demo_missing_routes(tmp_path):
    client=create_app(tmp_path,no_demo=True).test_client()
    for path in ['/api/demo','/api/runs/missing','/api/runs/missing/export','/api/runs/missing/audit']:
        assert client.get(path).status_code==404

def test_internal_error_hides_exception(client,csrf,monkeypatch,caplog):
    import app
    def fail(*a):raise RuntimeError('SENSITIVE_SENTINEL')
    monkeypatch.setattr(app.storage,'save',fail)
    response=client.post('/api/runs',json=client.get('/api/demo').json,headers=csrf)
    assert response.status_code==500
    assert 'SENSITIVE_SENTINEL' not in caplog.text and b'SENSITIVE_SENTINEL' not in response.data

def test_literal_html_user_and_annotation(client,csrf):
    text=client.get('/api/demo').json['text'].replace('arjun.patel','<img src=x onerror=alert(1)>')
    result=client.post('/api/runs',json={'text':text},headers=csrf).json
    assert '<img src=x onerror=alert(1)>' in [e['user'] for e in result['events']]
    source=Path('static/app.js').read_text()
    assert 'innerHTML' not in source and '.textContent' in source
