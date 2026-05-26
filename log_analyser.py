def count_failed_logins(log_lines):
    """
    Counts the number of failed login attempts in a list of log lines.
    """
    count = 0
    for line in log_lines:
        if "FAILED_LOGIN" in line:
            count += 1
    return count


def find_suspicious_ips(log_lines, threshold=3):
    """
    Finds IP addresses with failed login attempts greater than or equal to the threshold.
    """
    failed_attempts = {}

    for line in log_lines:
        if "FAILED_LOGIN" in line:
            parts = line.split()
            ip_address = parts[-1]

            if ip_address not in failed_attempts:
                failed_attempts[ip_address] = 0

            failed_attempts[ip_address] += 1

    suspicious_ips = []

    for ip, count in failed_attempts.items():
        if count >= threshold:
            suspicious_ips.append(ip)

    return suspicious_ips


def read_log_file(filename):
    """
    Reads a log file and returns each line as a list.
    """
    with open(filename, "r") as file:
        return file.readlines()


if __name__ == "__main__":
    logs = read_log_file("sample_log.txt")

    total_failed = count_failed_logins(logs)
    suspicious_ips = find_suspicious_ips(logs)

    print("Total failed login attempts:", total_failed)
    print("Suspicious IP addresses:", suspicious_ips)
