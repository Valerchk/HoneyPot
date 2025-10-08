import os
import sys
import time
import threading
import smtplib
from dotenv import load_dotenv
from email.message import EmailMessage
from collections import Counter, defaultdict, deque
from scapy.all import sniff, get_if_list, TCP, IP, IPv6

load_dotenv()

# ------------- CONFIG -------------
REPORT_INTERVAL = 10        # seconds between compact reports
WINDOW_SECONDS = 60         # sliding window length for counting (seconds)
SSH_PORTS = {22, 2222}      # ports considered SSH/Cowrie (add 2222 if you use it)
SYN_FLAG = 0x02             # TCP SYN flag bitmask
# Suspicion thresholds (tunable)
TOTAL_PKT_THRESHOLD = 450    # if total packets in window > this -> suspicious
SSH_CONN_THRESHOLD = 20      # if TCP SYNs to SSH port in window > this -> suspicious (likely brute-force)
UNIQUE_SRC_THRESHOLD = 10    # many unique src IPs -> possible scan
ALERT_COOLDOWN = 120         # 120s for testing | (avoid spamming email)
# Email config via ENV variables (explained below)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER = os.getenv("SMTP_USER", "secretariat.lps.official@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "xtdu vchi sldx qmyi")
ALERT_TO = os.getenv("ALERT_TO", "valer.business.contact@gmail.com")
ALERT_FROM = os.getenv("ALERT_FROM", "no-reply@nosniff.com")

# ------------- Data structures -------------
# store timestamps for events (sliding window)
pkt_times = deque()                     # timestamps of all packets
port_counter = Counter()                # dest port => count in window
proto_counter = Counter()               # protocol (TCP/UDP/ICMP/OTHER) => count
syn_times_by_dstport = defaultdict(deque)  # dstport -> deque of timestamps of SYNs
src_counter = Counter()                 # src ip => count of packets in window

last_alert_time = 0
lock = threading.Lock()

# ------------- helper functions -------------
def cleanup_old_entries(now):
    """Remove events older than WINDOW_SECONDS from counters / deques."""
    cutoff = now - WINDOW_SECONDS
    # Clean pkt_times
    while pkt_times and pkt_times[0] < cutoff:
        pkt_times.popleft()
    # Clean port_counter and proto_counter and src_counter by rebuilding from per-event store is heavy.
    # We keep per-packet minimal info by storing small history list for ports and srcs per time slot.
    # Simpler: periodically rebuild counters from an auxiliary list of tuples (ts, dstport, proto, src)
    # To keep code simple and robust, we'll store small event list too.
    pass  # we use event_list approach below

# We'll keep a small event_list with tuples (ts, dstport, proto, src, is_syn)
event_list = deque()  # append (ts, dstport, proto_str, src_ip, is_syn)

def prune_event_list(now):
    cutoff = now - WINDOW_SECONDS
    while event_list and event_list[0][0] < cutoff:
        event_list.popleft()

def rebuild_counters(now):
    """Rebuild counters from event_list (keeps things consistent)."""
    prune_event_list(now)
    port_counter.clear()
    proto_counter.clear()
    src_counter.clear()
    for ts, dstport, proto, src, is_syn in event_list:
        if dstport:
            port_counter[dstport] += 1
        proto_counter[proto] += 1
        if src:
            src_counter[src] += 1

def human_readable_report(now):
    rebuild_counters(now)
    total_pkts = len(event_list)
    top_ports = port_counter.most_common(10)
    top_srcs = src_counter.most_common(10)
    tcp_syns_to_ssh = 0
    for p in SSH_PORTS:
        # count SYN events stored per port
        for ts, dstport, proto, src, is_syn in event_list:
            if is_syn and dstport == p:
                tcp_syns_to_ssh += 1

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        "window_seconds": WINDOW_SECONDS,
        "total_packets": total_pkts,
        "protocols": dict(proto_counter),
        "top_ports": top_ports,
        "top_srcs": top_srcs,
        "tcp_syns_to_ssh": tcp_syns_to_ssh,
    }
    return report

def is_suspicious(report):
    """Decide if the current window is suspicious (simple heuristics)."""
    if report["total_packets"] >= TOTAL_PKT_THRESHOLD:
        return True, "high_packet_rate"
    if report["tcp_syns_to_ssh"] >= SSH_CONN_THRESHOLD:
        return True, "ssh_bruteforce"
    if len(report["top_srcs"]) >= UNIQUE_SRC_THRESHOLD and report["total_packets"] >= (TOTAL_PKT_THRESHOLD // 2):
        return True, "scan_many_srcs"
    return False, None

def send_alert_email(subject, body, debug=True):
    """
    Robust email sender:
    - uses SMTP_SSL when SMTP_PORT == 465
    - uses STARTTLS otherwise (e.g. 587)
    - prints debug output and returns True on success
    """
    global last_alert_time
    now = time.time()
    if now - last_alert_time < ALERT_COOLDOWN:
        if debug: print("[ALERT] suppressed by cooldown")
        return False

    if not SMTP_USER or not SMTP_PASS:
        print("[ALERT] SMTP credentials missing. Will not send.")
        last_alert_time = now
        return False

    msg = EmailMessage()
    msg["From"] = ALERT_FROM
    msg["To"] = ALERT_TO
    msg["Subject"] = subject
    msg.set_content(body)

    # Try SMTPS (implicit SSL) when port == 465
    try:
        if SMTP_PORT == 465:
            if debug: print(f"[ALERT] Using SMTP_SSL to {SMTP_SERVER}:{SMTP_PORT}")
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=30) as s:
                if debug: s.set_debuglevel(1)
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
            print("[ALERT] Email sent via SMTP_SSL (465).")
            last_alert_time = now
            return True

        # Otherwise try STARTTLS (typical for 587)
        if debug: print(f"[ALERT] Using SMTP + STARTTLS to {SMTP_SERVER}:{SMTP_PORT}")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30) as s:
            if debug: s.set_debuglevel(1)
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print("[ALERT] Email sent via STARTTLS.")
        last_alert_time = now
        return True

    except Exception as e:
        # Print traceback for debugging
        print("[ALERT] Failed to send email:", repr(e))
        
    # final fallback: print body
    print("[ALERT] Could not send email. Alert body below:")
    print("Subject:", subject)
    print(body)
    last_alert_time = now
    return False

# ------------- packet callback & collector -------------
def pkt_callback(pkt):
    now = time.time()
    # extract minimal important facts (dst port, proto, src)
    dstport = None
    src_ip = None
    proto_str = "OTHER"
    is_syn = False

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src

    if pkt.haslayer(TCP):
        proto_str = "TCP"
        try:
            dport = int(pkt[TCP].dport)
            dstport = dport
            flags = int(pkt[TCP].flags)
            # SYN detection
            if flags & SYN_FLAG:
                is_syn = True
        except Exception:
            dstport = None
    else:
        # Could add UDP/ICMP checks...
        if pkt.haslayer("UDP"):
            proto_str = "UDP"
        else:
            proto_str = pkt.__class__.__name__

    # store event (thread-safe)
    with lock:
        event_list.append((now, dstport, proto_str, src_ip, is_syn))

    # We do NOT print every packet; keep console clean
    # Optionally: debug print for specific conditions
    # if is_syn and dstport in SSH_PORTS:
    #     print(f"[DEBUG] SYN to SSH: {src_ip}->{dstport}")

# ------------- reporter thread -------------
def reporter_loop():
    while True:
        time.sleep(REPORT_INTERVAL)
        now = time.time()
        with lock:
            report = human_readable_report(now)
        # Print compact report
        print("="*60)
        print(f"[NIDS REPORT @ {report['timestamp']}] window={report['window_seconds']}s")
        print(f"Total packets (window): {report['total_packets']}")
        print("Protocols:", report["protocols"])
        print("Top dest ports:", report["top_ports"][:8])
        print("Top src IPs:", report["top_srcs"][:8])
        print("TCP SYNs to SSH ports:", report["tcp_syns_to_ssh"])
        print("="*60)

        suspicious, reason = is_suspicious(report)
        if suspicious:
            subject = f"[ALERT] Suspicious activity detected: {reason}"
            body = (
                f"Time: {report['timestamp']}\n"
                f"Reason: {reason}\n\n"
                f"Total packets (window): {report['total_packets']}\n"
                f"TCP SYNs to SSH ports: {report['tcp_syns_to_ssh']}\n"
                f"Top dest ports: {report['top_ports'][:10]}\n"
                f"Top src IPs: {report['top_srcs'][:10]}\n\n"
                "This is an automated alert from the local NIDS."
            )
            send_alert_email(subject, body)

# ------------- interface helpers -------------
def find_loopback_iface():
    ifaces = get_if_list()
    candidates = []
    for i, iface in enumerate(ifaces):
        name = iface.lower()
        if "loopback" in name or "npcap" in name or "loop" in name or iface.lower() in ("lo0","lo"):
            candidates.append((i, iface))
    return candidates, ifaces

def choose_iface(candidates, ifaces):
    if candidates:
        print("Loopback candidate(s) found:")
        for i, iface in candidates:
            print(f"  [{i}] {iface}")
        idx, iface = candidates[0]
        print(f"\nAuto-using: [{idx}] {iface}\n")
        return iface
    else:
        print("No automatic loopback found. Available interfaces:")
        for i, iface in enumerate(ifaces):
            print(f"  [{i}] {iface}")
        try:
            choice = input("\nEnter index of interface to use (or ENTER to cancel): ")
            if choice.strip() == "":
                sys.exit("Capture cancelled.")
            idx = int(choice.strip())
            return ifaces[idx]
        except Exception as e:
            sys.exit(f"Invalid index or error: {e}")

# ------------- main -------------
def main():
    candidates, ifaces = find_loopback_iface()
    iface = choose_iface(candidates, ifaces)
    print("Starting capture on interface:", iface)
    print("You can run your attack in another terminal now (eg. your brute-force script).")
    # start reporter thread
    t = threading.Thread(target=reporter_loop, daemon=True)
    t.start()
    try:
        sniff(iface=iface, prn=pkt_callback, store=False)
    except OSError as e:
        print("\nOSError when opening interface:", e)
        print(" - Run Python as admin/root or enable loopback capture support on your OS.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping capture (keyboard interrupt).")
        sys.exit(0)
    except Exception as e:
        print("\nUnexpected error:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
