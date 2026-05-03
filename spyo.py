import sys
import threading
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, conf, Ether, wrpcap
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Footer, DataTable, Static, RichLog, Label
from textual.binding import Binding
from textual.screen import ModalScreen

VERSION = "1.0.0"
MAX_PACKETS = 1000
UPDATE_INTERVAL = 0.3

lock = threading.Lock()
capture_running = True
current_interface = ""
total_packets = 0

packets = deque(maxlen=MAX_PACKETS)
saved_packets_raw = []
show_detail = False
detail_pkt = None
selected_row = 0

stats = {
    "talkers": defaultdict(int),
    "protocols": defaultdict(int),
    "ports": defaultdict(int),
    "alerts": deque(maxlen=50),
    "connections": defaultdict(set),
}

SERVICE_MAP = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
    25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    3389: "RDP", 5900: "VNC", 23: "Telnet",
}

ICMP_TYPES = {
    0: "Echo Reply", 8: "Echo Request",
    3: "Dest Unreach", 11: "TTL Exceeded", 5: "Redirect"
}


def capture_packets(interface):
    global total_packets

    def handle(pkt):
        global total_packets
        if not capture_running:
            return

        with lock:
            total_packets += 1
            saved_packets_raw.append(pkt)
            if len(saved_packets_raw) > 5000:
                saved_packets_raw.pop(0)

            timestamp = datetime.now().strftime("%H:%M:%S")

            if pkt.haslayer(ARP):
                packets.append((timestamp, "ARP", pkt[ARP].psrc, pkt[ARP].pdst,
                               len(pkt), "Who has?" if pkt[ARP].op == 1 else "Reply"))

            elif pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                size = len(pkt)
                stats["connections"][src_ip].add(dst_ip)

                if pkt.haslayer(TCP):
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                    flags = pkt[TCP].flags
                    fstr = _tcp_flags(flags)
                    svc = SERVICE_MAP.get(dport, SERVICE_MAP.get(sport, ""))
                    service_tag = f"[{svc}]" if svc else ""
                    packets.append((timestamp, "TCP", f"{src_ip}:{sport}",
                                   f"{dst_ip}:{dport}", size, f"{fstr} {service_tag}".strip()))
                    stats["ports"][str(dport)] += 1
                    if flags & 0x02 and not flags & 0x10:
                        stats["alerts"].append(f"SYN -> {dst_ip}:{dport}")

                elif pkt.haslayer(UDP):
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport
                    info = ""
                    if dport == 53 or sport == 53:
                        info = "DNS"
                        try:
                            if pkt.haslayer(DNS) and pkt[DNS].qd:
                                info += f" {pkt[DNS].qd.qname.decode()}"
                        except:
                            pass
                    packets.append((timestamp, "UDP", f"{src_ip}:{sport}",
                                   f"{dst_ip}:{dport}", size, info))
                    stats["ports"][str(dport)] += 1

                elif pkt.haslayer(ICMP):
                    info = ICMP_TYPES.get(pkt[ICMP].type, f"Type={pkt[ICMP].type}")
                    packets.append((timestamp, "ICMP", src_ip, dst_ip, size, info))

                else:
                    packets.append((timestamp, "IP", src_ip, dst_ip, size, ""))

                stats["talkers"][src_ip] += size
                stats["protocols"][pkt[IP].proto] += 1

    sniff(iface=interface, prn=handle, store=0)


def _tcp_flags(flags):
    parts = []
    if flags & 0x02: parts.append("SYN")
    if flags & 0x10: parts.append("ACK")
    if flags & 0x01: parts.append("FIN")
    if flags & 0x04: parts.append("RST")
    if flags & 0x08: parts.append("PSH")
    return " ".join(parts)


class HelpScreen(ModalScreen):
    CSS = "#help-container { align: center middle; background: $surface; border: thick $primary; padding: 2 4; width: 50; height: 16; }"
    def compose(self) -> ComposeResult:
        with Container(id="help-container"):
            yield Label("[bold yellow]spyo - Help[/]\n")
            yield Label(
                "[bold]Space[/]   Pause/Resume\n"
                "[bold]F1[/]      Help\n"
                "[bold]F3[/]      Clear packets\n"
                "[bold]F4[/]      Save PCAP\n"
                "[bold]Up/Down[/] Select packet\n"
                "[bold]Enter[/]   Show packet detail\n"
                "[bold]Esc[/]     Back to packets\n"
                "[bold]Q[/]       Quit\n\n"
                "[dim]Any key to close[/]"
            )
    def on_key(self): self.dismiss()


class SpyoApp(App):

    CSS = """
    Screen { layout: vertical; background: $background; }
    #top-bar { height: 1; background: $primary-darken-1; color: $text; padding: 0 1; }
    #packet-table { height: 1fr; border: solid $primary; }
    #detail-view { height: 1fr; border: solid $secondary; padding: 1 2; background: $surface; }
    #bottom-area { height: 11; }
    #left-panel { width: 1fr; border: solid $primary; background: $surface; }
    #right-panel { width: 1fr; border: solid $primary; background: $surface; }
    DataTable > .datatable--header { background: $primary-darken-2; color: $text; text-style: bold; }
    RichLog { padding: 0 1; }
    .hidden { display: none; }
    """

    BINDINGS = [
        Binding("space", "pause_resume", "Pause"),
        Binding("f1", "show_help", "Help"),
        Binding("f3", "clear_packets", "Clear"),
        Binding("f4", "save_pcap", "Save"),
        Binding("up", "cursor_up", ""),
        Binding("down", "cursor_down", ""),
        Binding("enter", "packet_detail", "Detail"),
        Binding("escape", "show_packets", "Back"),
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Static(f"spyo v{VERSION}", id="top-bar")
        yield DataTable(id="packet-table")
        yield Static("", id="detail-view", classes="hidden")
        with Horizontal(id="bottom-area"):
            yield RichLog(id="left-panel", markup=True, wrap=True)
            yield RichLog(id="right-panel", markup=True, wrap=True)
        yield Footer()

    def on_mount(self):
        table = self.query_one("#packet-table", DataTable)
        table.add_columns("Time", "Proto", "Source", "Destination", "Size", "Info")
        table.show_header = True
        table.cursor_type = "row"
        table.zebra_stripes = True

        global current_interface
        current_interface = _get_interface()

        self._update_status()

        self.capture_thread = threading.Thread(
            target=capture_packets, args=(current_interface,), daemon=True
        )
        self.capture_thread.start()

        self.set_interval(UPDATE_INTERVAL, self._refresh_ui)

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        global selected_row
        selected_row = event.cursor_row
        self._show_detail_for_row(selected_row)

    def _show_detail_for_row(self, row_index):
        global show_detail, detail_pkt, selected_row
        with lock:
            pkt_list = list(packets)
            if 0 <= row_index < len(pkt_list):
                detail_pkt = pkt_list[row_index]
                show_detail = True
                selected_row = row_index

    def _refresh_ui(self):
        with lock:
            table = self.query_one("#packet-table", DataTable)
            detail = self.query_one("#detail-view", Static)
            
            if show_detail and detail_pkt:
                table.add_class("hidden")
                detail.remove_class("hidden")
                detail.update(self._format_detail(detail_pkt))
            else:
                detail.add_class("hidden")
                table.remove_class("hidden")
                
                current = len(table.rows)
                new = list(packets)[current:]

                for pkt in new:
                    t, proto, src, dst, size, info = pkt
                    s = _fmt_size(size)
                    table.add_row(t, proto, src[:30], dst[:30], s, info[:45])

                if new and not show_detail:
                    table.move_cursor(row=len(table.rows) - 1)

            self._update_status()
            self._update_left_panel()
            self._update_right_panel()

    def _format_detail(self, pkt):
        size_str = _fmt_size(pkt[4]) if isinstance(pkt[4], (int, float)) else str(pkt[4])
        info_str = str(pkt[5]) if len(pkt) > 5 else ""
        
        return "\n".join([
            "PACKET DETAIL",
            "",
            f"Time:        {pkt[0]}",
            f"Protocol:    {pkt[1]}",
            f"Source:      {pkt[2]}",
            f"Destination: {pkt[3]}",
            f"Size:        {size_str}",
            f"Info:        {info_str}",
            "",
            "Connection Details:",
            f"  Source IP:      {pkt[2].split(':')[0] if ':' in pkt[2] else pkt[2]}",
            f"  Dest IP:        {pkt[3].split(':')[0] if ':' in pkt[3] else pkt[3]}",
            f"  Source Port:    {pkt[2].split(':')[1] if ':' in pkt[2] else 'N/A'}",
            f"  Dest Port:      {pkt[3].split(':')[1] if ':' in pkt[3] else 'N/A'}",
            "",
            "Use Up/Down to select | Enter to view | ESC to return"
        ])

    def _update_status(self):
        bar = self.query_one("#top-bar", Static)
        state = "PAUSED" if not capture_running else "RUNNING"
        mode = "DETAIL" if show_detail else "PACKETS"
        row_info = f"Row: {selected_row}" if not show_detail else ""
        bar.update(f" {current_interface} | {state} | {mode} | Packets: {total_packets} | {row_info}")

    def _update_left_panel(self):
        panel = self.query_one("#left-panel", RichLog)
        panel.clear()
        panel.write("[bold reverse]  TOP TALKERS  [/]\n")
        sorted_t = sorted(stats["talkers"].items(), key=lambda x: x[1], reverse=True)[:6]
        total = sum(stats["talkers"].values()) or 1
        for ip, sz in sorted_t:
            pct = (sz / total) * 100
            b = int(pct / 4)
            bar = "|" * min(b, 25) + "." * max(25 - b, 0)
            panel.write(f" {ip:<15} {bar} {pct:5.1f}%")

        panel.write("\n[bold reverse]  PROTOCOLS  [/]\n")
        sorted_p = sorted(stats["protocols"].items(), key=lambda x: x[1], reverse=True)
        tp = sum(stats["protocols"].values()) or 1
        for proto, cnt in sorted_p[:5]:
            pct = (cnt / tp) * 100
            panel.write(f"  {proto:<6} {cnt:>6} ({pct:5.1f}%)")

        panel.write(f"\n[bold reverse]  BUFFER  [/]")
        panel.write(f"  Stored: {len(packets)}/{MAX_PACKETS}")
        panel.write(f"  Total : {total_packets}")

    def _update_right_panel(self):
        panel = self.query_one("#right-panel", RichLog)
        panel.clear()
        panel.write("[bold reverse]  TOP PORTS  [/]\n")
        sorted_po = sorted(stats["ports"].items(), key=lambda x: x[1], reverse=True)[:6]
        for port, cnt in sorted_po:
            svc = SERVICE_MAP.get(int(port), "")
            panel.write(f"  {port:<6} {cnt:>6}  {svc}")

        panel.write("\n[bold reverse]  ALERTS  [/]\n")
        if stats["alerts"]:
            for a in list(stats["alerts"])[-5:]:
                panel.write(f"[red]! {a}[/]")
        else:
            panel.write("  [dim]None[/]")

    def action_pause_resume(self):
        global capture_running
        capture_running = not capture_running

    def action_show_help(self):
        self.push_screen(HelpScreen())

    def action_clear_packets(self):
        global show_detail, detail_pkt, selected_row
        with lock:
            packets.clear()
            saved_packets_raw.clear()
            self.query_one("#packet-table", DataTable).clear()
            show_detail = False
            detail_pkt = None
            selected_row = 0
            stats["alerts"].append("Cleared")

    def action_save_pcap(self):
        with lock:
            if saved_packets_raw:
                fn = f"spyo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                wrpcap(fn, saved_packets_raw[-1000:])
                stats["alerts"].append(f"Saved: {fn}")
            else:
                stats["alerts"].append("Nothing to save")

    def action_cursor_up(self):
        global selected_row
        if not show_detail:
            selected_row = max(0, selected_row - 1)
            table = self.query_one("#packet-table", DataTable)
            table.move_cursor(row=selected_row)

    def action_cursor_down(self):
        global selected_row
        if not show_detail:
            max_row = len(self.query_one("#packet-table", DataTable).rows) - 1
            selected_row = min(max_row, selected_row + 1)
            table = self.query_one("#packet-table", DataTable)
            table.move_cursor(row=selected_row)

    def action_packet_detail(self):
        self._show_detail_for_row(selected_row)

    def action_show_packets(self):
        global show_detail, detail_pkt
        show_detail = False
        detail_pkt = None


def _get_interface():
    if "-i" in sys.argv:
        idx = sys.argv.index("-i")
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    return conf.iface


def _fmt_size(size):
    if isinstance(size, str):
        return size
    if size < 1024: return f"{size}B"
    elif size < 1024*1024: return f"{size/1024:.1f}KB"
    else: return f"{size/1024/1024:.1f}MB"


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("spyo - spy io Packet sniffer\n")
        print("Usage: sudo python3 spyo.py [-i eth0]")
        print("Keys: Up/Down=Select Space=Pause F1=Help F3=Clear F4=Save Enter=Detail Esc=Back Q=Quit")
        sys.exit(0)

    try:
        SpyoApp().run()
    except PermissionError:
        print("Error: Need root Run: sudo python3 spyo.py")
    except KeyboardInterrupt:
        print("\nDone")
