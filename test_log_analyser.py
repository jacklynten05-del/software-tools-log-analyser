from log_analyser import count_failed_logins, find_suspicious_ips


def test_count_failed_logins():
    logs = [
        "2025-05-01 FAILED_LOGIN user=guest ip=192.168.1.20",
        "2025-05-01 SUCCESS_LOGIN user=admin ip=192.168.1.10",
        "2025-05-01 FAILED_LOGIN user=test ip=192.168.1.30",
    ]

    assert count_failed_logins(logs) == 2


def test_find_suspicious_ips():
    logs = [
        "2025-05-01 FAILED_LOGIN user=guest ip=192.168.1.20",
        "2025-05-01 FAILED_LOGIN user=guest ip=192.168.1.20",
        "2025-05-01 FAILED_LOGIN user=guest ip=192.168.1.20",
        "2025-05-01 FAILED_LOGIN user=test ip=192.168.1.30",
    ]

    assert find_suspicious_ips(logs, threshold=3) == ["ip=192.168.1.20"]


def test_no_failed_logins():
    logs = [
        "2025-05-01 SUCCESS_LOGIN user=admin ip=192.168.1.10",
        "2025-05-01 SUCCESS_LOGIN user=student ip=192.168.1.30",
    ]

    assert count_failed_logins(logs) == 0
