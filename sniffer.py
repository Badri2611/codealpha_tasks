import curses
from scapy.all import sniff

# Initialize curses for a live display
def start_curses_interface(stdscr):
    # Disable cursor and enable instant refresh
    curses.curs_set(0)
    stdscr.nodelay(1)
    stdscr.timeout(100)
    stdscr.clear()
    
    stdscr.addstr(0, 0, "Live Packet Delivery Tracker", curses.A_BOLD)
    stdscr.addstr(1, 0, "Press 'q' to quit.")
    return stdscr

# Display packet details in curses interface
def display_packet(stdscr, packet_count, packet_info):
    max_y, max_x = stdscr.getmaxyx()
    if packet_count >= max_y - 3:
        stdscr.clear()
        stdscr.addstr(0, 0, "Live Packet Delivery Tracker", curses.A_BOLD)
        stdscr.addstr(1, 0, "Press 'q' to quit.")
        packet_count = 2

    stdscr.addstr(packet_count, 0, packet_info[:max_x])
    stdscr.refresh()

    return packet_count + 1

# Callback for processing packets
def packet_handler(packet, stdscr, packet_count):
    try:
        if packet.haslayer('IP'):
            ip_src = packet['IP'].src
            ip_dst = packet['IP'].dst
            protocol = "TCP" if packet.haslayer('TCP') else "UDP" if packet.haslayer('UDP') else "ICMP" if packet.haslayer('ICMP') else "Other"
            packet_info = f"Source: {ip_src} -> Destination: {ip_dst} | Protocol: {protocol}"
            return display_packet(stdscr, packet_count, packet_info)
    except Exception as e:
        error_info = f"Error processing packet: {e}"
        return display_packet(stdscr, packet_count, error_info)
    return packet_count

# Start packet sniffing
def start_sniffing(interface, stdscr):
    packet_count = 2
    def sniff_callback(packet):
        nonlocal packet_count
        packet_count = packet_handler(packet, stdscr, packet_count)

    sniff(iface=interface, prn=sniff_callback, store=False)

# Main function
def main():
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")

    curses.wrapper(lambda stdscr: start_sniffing(interface, start_curses_interface(stdscr)))

if __name__ == "__main__":
    main()