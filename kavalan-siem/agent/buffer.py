"""
buffer.py - Leaky-Bucket Ring Buffer & Rate Limiter for Kavalan Agent (Tier 1)

Protects host CPU and network from log storm spikes.
Features:
  1. Thread-safe circular ring buffer with bounded capacity
  2. Strict max_eps (events per second) throttling via token/delay pacing
  3. Buffer states: NORMAL (<80%), WARNING (80-99%), FLOOD (100%)
  4. Monotonic sequential tx_id (Transaction ID) tracking for replay attack prevention
"""

from collections import deque
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


class BufferState:
    NORMAL = "normal"
    WARNING = "warning"
    FLOOD = "flood"


class EventBuffer:
    """Thread-safe bounded ring buffer with leaky-bucket rate limiting and replay protection."""

    def __init__(self, capacity: int = 5000, max_eps: int = 500, warn_ratio: float = 0.8):
        self.capacity = max(1, capacity)
        self.max_eps = max(1, max_eps)
        self.warn_threshold = int(self.capacity * warn_ratio)
        self.queue: deque = deque(maxlen=self.capacity)
        self.lock = threading.Lock()
        self.tx_id: int = 0
        self.dropped_events: int = 0
        self.last_pop_time: float = 0.0

    @property
    def state(self) -> str:
        with self.lock:
            qlen = len(self.queue)
            if qlen >= self.capacity:
                return BufferState.FLOOD
            elif qlen >= self.warn_threshold:
                return BufferState.WARNING
            return BufferState.NORMAL

    def push(self, event: Dict[str, Any]) -> bool:
        """
        Pushes an event into the ring buffer.
        If buffer is in FLOOD state, drops low-priority events to safeguard endpoint resources.
        Returns True if queued, False if dropped due to capacity overflow.
        """
        with self.lock:
            if len(self.queue) >= self.capacity:
                self.dropped_events += 1
                return False
            self.queue.append(event)
            return True

    def push_many(self, events: List[Dict[str, Any]]) -> int:
        """Pushes multiple events, returns number of successfully queued events."""
        queued = 0
        with self.lock:
            for ev in events:
                if len(self.queue) >= self.capacity:
                    self.dropped_events += 1
                else:
                    self.queue.append(ev)
                    queued += 1
        return queued

    def pop_batch(self, max_batch_size: int = 100) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Pops a batch of events respecting max_eps pace.
        Returns (tx_id, events_batch).
        """
        batch: List[Dict[str, Any]] = []
        with self.lock:
            if not self.queue:
                return self.tx_id, []

            # Determine batch count capped by max_batch_size and max_eps
            count = min(len(self.queue), max_batch_size, self.max_eps)
            for _ in range(count):
                batch.append(self.queue.popleft())

            self.tx_id += 1
            curr_tx = self.tx_id

        # Leaky-bucket pacing: ensure we do not exceed max_eps
        now = time.time()
        elapsed = now - self.last_pop_time
        min_interval = len(batch) / float(self.max_eps)
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self.last_pop_time = time.time()

        return curr_tx, batch

    def __len__(self) -> int:
        with self.lock:
            return len(self.queue)
