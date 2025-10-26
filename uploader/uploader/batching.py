from __future__ import annotations
import time, orjson

class Batch:
    def __init__(self, max_events:int, max_bytes:int, max_seconds:float):
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.max_seconds = max_seconds
        self.reset()

    def reset(self):
        self.events = []
        self.size = 0
        self.started = time.time()

    def add_json_line(self, raw_line:str) -> bool:
        if not raw_line: 
            return True
        try:
            evt = orjson.loads(raw_line)
        except Exception:
            return True
        b = orjson.dumps(evt)
        if self.events and (len(self.events)+1 > self.max_events or self.size+len(b)+1 > self.max_bytes):
            return False
        self.events.append(evt)
        self.size += len(b) + 1
        return True

    def should_flush(self) -> bool:
        return (self.events and (
                len(self.events) >= self.max_events or
                self.size >= self.max_bytes or
                (time.time() - self.started) >= self.max_seconds))
