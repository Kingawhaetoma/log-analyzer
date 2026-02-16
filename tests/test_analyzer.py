from log_analyzer import parse_events, analyze

def test_parse_linux_events():
    lines = [
        "Feb 16 00:01:10 host sshd[111]: Failed password for invalid user admin from 192.168.1.10 port 55222 ssh2",
        "Feb 16 00:02:11 host sshd[111]: Failed password for invalid user admin from 192.168.1.10 port 55223 ssh2",
        "Feb 16 00:20:10 host sshd[222]: Failed password for invalid user root from 10.0.0.5 port 41414 ssh2",
    ]
    events = parse_events(lines, assumed_year=2026)
    assert len(events) == 3
    assert events[0].ip == "192.168.1.10"
    assert events[-1].ip == "10.0.0.5"

def test_window_detection_flags_bruteforce():
    lines = [
        "Feb 16 00:01:10 host sshd[111]: Failed password for invalid user admin from 192.168.1.10 port 1 ssh2",
        "Feb 16 00:02:11 host sshd[111]: Failed password for invalid user admin from 192.168.1.10 port 2 ssh2",
        "Feb 16 00:03:12 host sshd[111]: Failed password for invalid user admin from 192.168.1.10 port 3 ssh2",
        "Feb 16 00:03:50 host sshd[111]: Failed password for invalid user admin from 192.168.1.10 port 4 ssh2",
        "Feb 16 00:20:10 host sshd[222]: Failed password for invalid user root from 10.0.0.5 port 5 ssh2",
    ]
    events = parse_events(lines, assumed_year=2026)
    report = analyze(events, threshold=4, window_minutes=10)

    assert report["summary"]["total_events"] == 5
    assert report["summary"]["suspicious_ips"] == 1
    assert report["suspicious"][0]["ip"] == "192.168.1.10"
    assert report["suspicious"][0]["count_in_window"] == 4