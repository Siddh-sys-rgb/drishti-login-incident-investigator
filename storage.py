"""Immutable event replays with transactional revision-checked alert annotations."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

def connect(path):
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    return db

def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created TEXT, result TEXT); CREATE TABLE IF NOT EXISTS annotations (run_id TEXT, alert_id TEXT, status TEXT, annotation TEXT, investigator TEXT, revision INTEGER, PRIMARY KEY(run_id,alert_id)); CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, alert_id TEXT, created TEXT, action TEXT, investigator TEXT, revision INTEGER);')

def save(path, result):
    # Content identity ignores upload ordering, duplicate count and mutable annotations.
    run_id = hashlib.sha256(json.dumps(result['events'], sort_keys=True).encode()).hexdigest()[:24]
    item = dict(result, id=run_id, created=datetime.now(timezone.utc).isoformat())
    with connect(path) as db:
        db.execute('INSERT OR IGNORE INTO runs VALUES (?,?,?)', (run_id, item['created'], json.dumps(item)))
    return get(path, run_id)

def get(path, run_id):
    with connect(path) as db:
        row = db.execute('SELECT result FROM runs WHERE id=?', (run_id,)).fetchone()
        annotations = db.execute('SELECT * FROM annotations WHERE run_id=?', (run_id,)).fetchall()
    if not row:
        return None
    result = json.loads(row['result']); by_id = {a['alert_id']: dict(a) for a in annotations}
    for alert in result['alerts']:
        if alert['id'] in by_id:
            alert.update({k: by_id[alert['id']][k] for k in ('status', 'annotation', 'investigator', 'revision')})
    return result

def history(path):
    with connect(path) as db:
        rows = db.execute('SELECT result FROM runs ORDER BY created DESC LIMIT 40').fetchall()
    return [dict(id=(r:=json.loads(row['result']))['id'], created=r['created'], event_count=r['event_count'], alert_count=len(r['alerts'])) for row in rows]

class Conflict(ValueError):
    pass

def annotate(path, run_id, alert_id, data):
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        current = db.execute('SELECT revision FROM annotations WHERE run_id=? AND alert_id=?', (run_id, alert_id)).fetchone()
        revision = current['revision'] if current else 0
        if revision != data['revision']:
            raise Conflict('This alert changed. Refresh before saving another note.')
        revision += 1
        db.execute('INSERT INTO annotations VALUES (?,?,?,?,?,?) ON CONFLICT(run_id,alert_id) DO UPDATE SET status=excluded.status,annotation=excluded.annotation,investigator=excluded.investigator,revision=excluded.revision', (run_id, alert_id, data['status'], data['annotation'], data['investigator'], revision))
        db.execute('INSERT INTO audit(run_id,alert_id,created,action,investigator,revision) VALUES (?,?,?,?,?,?)', (run_id, alert_id, datetime.now(timezone.utc).isoformat(), data['status'], data['investigator'], revision))
    return get(path, run_id)

def audit(path, run_id):
    with connect(path) as db:
        return [dict(row) for row in db.execute('SELECT created,alert_id,action,investigator,revision FROM audit WHERE run_id=? ORDER BY id', (run_id,))]
