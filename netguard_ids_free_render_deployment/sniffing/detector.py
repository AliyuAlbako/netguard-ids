
from collections import defaultdict, deque
import time

# Detection configuration
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW_SECONDS = 10

# Store packet events for each source-destination pair
ip_port_events = defaultdict(deque)

# Keep track of pairs that have already triggered an alert
alerted_pairs = set()


def detect_port_scan(src_ip, dst_ip, port):

    current_time = time.monotonic()

    # Identify the source and destination computer
    connection = (src_ip, dst_ip)

    # Get the event history for this connection
    events = ip_port_events[connection]

    # Record the newly observed destination port
    events.append((current_time, port))

    # Remove events older than the 10-second window
    while events and current_time - events[0][0] > TIME_WINDOW_SECONDS:
        events.popleft()

    # Count unique destination ports in the current window
    unique_ports = {event[1] for event in events}

    print(
        f"[DETECTION] {src_ip} -> {dst_ip}: "
        f"{len(unique_ports)} unique ports in "
        f"{TIME_WINDOW_SECONDS} seconds"
    )

    # Reset alert status when activity drops below threshold
    if len(unique_ports) < PORT_SCAN_THRESHOLD:
        alerted_pairs.discard(connection)
        return False

    # Generate only one alert for this active detection window
    if connection not in alerted_pairs:
        alerted_pairs.add(connection)
        return True

    return False
