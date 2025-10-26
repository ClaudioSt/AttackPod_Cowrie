import time, json

def follow_json_lines(path, sleep=0.5):
    """Tailt eine NDJSON-Datei und liefert dicts."""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(0, 2)  # ans Ende
        while True:
            line = f.readline()
            if not line:
                time.sleep(sleep); continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue
