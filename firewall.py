import datetime

RULES_FILE = "rules.txt"
LOG_FILE = "firewall.log"

blocked_ips = set()
blocked_ports = set()


def load_rules():
    blocked_ips.clear()
    blocked_ports.clear()

    try:
        with open(RULES_FILE, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split()

                if parts[0] == "BLOCK_IP" and len(parts) == 2:
                    blocked_ips.add(parts[1])

                elif parts[0] == "BLOCK_PORT" and len(parts) == 2:
                    try:
                        blocked_ports.add(int(parts[1]))
                    except ValueError:
                        pass
    except FileNotFoundError:
        print("Rules file not found. No rules loaded.")


def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write("[{}] {}\n".format(timestamp, message))


def check_packet(source_ip, port):
    if source_ip in blocked_ips:
        log_event("BLOCKED IP {}".format(source_ip))
        return False

    if port in blocked_ports:
        log_event("BLOCKED PORT {} from {}".format(port, source_ip))
        return False

    log_event("ALLOWED {} -> PORT {}".format(source_ip, port))
    return True


def main():
    load_rules()
    print("🔥 Python Firewall Started (3.13 compatible)")
    print("Type 'exit' to stop\n")

    while True:
        source_ip = input("Source IP: ").strip()
        if source_ip.lower() == "exit":
            print("Firewall stopped.")
            break

        try:
            port = int(input("Port: ").strip())
        except ValueError:
            print("Invalid port number.\n")
            continue

        if check_packet(source_ip, port):
            print("✅ Packet Allowed\n")
        else:
            print("❌ Packet Blocked\n")


if __name__ == "__main__":
    main()
