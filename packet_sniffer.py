#!/usr/bin/env python3
"""
Enhanced Network Sniffer with protocol analysis, logging, and statistics
"""

# Import required modules
import sys          # System-specific functions
import argparse     # Command-line argument parsing
from datetime import datetime  # For timestamping packets
from scapy.all import *        # Main packet manipulation library
from scapy.layers import http  # HTTP protocol analysis

class EnhancedSniffer:
    def __init__(self):
        """Initialize the sniffer with counters and tracking variables"""
        self.packet_count = 0   # Total packets processed
        self.running = True     # Control flag for sniffing loop
        # Dictionary to track protocol counts
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}

    def handle_packet(self, packet, log_file=None, verbose=False):
        """
        Process each captured packet and extract relevant information
        Args:
            packet: The captured network packet
            log_file: File object for logging (optional)
            verbose: Whether to print to console
        """
        # Create timestamp with microsecond precision
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        self.packet_count += 1  # Increment packet counter
        
        # Initialize output string with basic info
        output = f"[{timestamp}] Packet #{self.packet_count}\n"
        
        # Check for and process IP layer
        if packet.haslayer(IP):
            ip = packet[IP]
            # Add IP header information
            output += f"  IP: {ip.src} -> {ip.dst} | TTL: {ip.ttl}\n"
            
            # Process TCP packets
            if packet.haslayer(TCP):
                self.protocol_stats['TCP'] += 1
                tcp = packet[TCP]
                # Add TCP header information
                output += f"  TCP: {tcp.sport} -> {tcp.dport} | Flags: {tcp.flags}\n"
                
                # Process HTTP requests
                if packet.haslayer(http.HTTPRequest):
                    http_layer = packet[http.HTTPRequest]
                    output += "  HTTP Request:\n"
                    output += f"    Host: {http_layer.Host}\n"
                    output += f"    Path: {http_layer.Path}\n"
                    output += f"    Method: {http_layer.Method}\n"
                # Process HTTP responses
                elif packet.haslayer(http.HTTPResponse):
                    http_layer = packet[http.HTTPResponse]
                    output += "  HTTP Response:\n"
                    output += f"    Status Code: {http_layer.Status_Code}\n"
                    output += f"    Reason: {http_layer.Reason_Phrase}\n"
                
            # Process UDP packets
            elif packet.haslayer(UDP):
                self.protocol_stats['UDP'] += 1
                udp = packet[UDP]
                output += f"  UDP: {udp.sport} -> {udp.dport}\n"
                
                # Process DNS packets
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    output += "  DNS:\n"
                    if dns.qr == 0:  # DNS Query
                        output += f"    Query: {dns.qd.qname.decode()}\n"
                    else:  # DNS Response
                        for i in range(dns.ancount):
                            output += f"    Answer: {dns.an[i].rdata}\n"
            
            # Process ICMP packets
            elif packet.haslayer(ICMP):
                self.protocol_stats['ICMP'] += 1
                icmp = packet[ICMP]
                output += f"  ICMP: Type {icmp.type} | Code {icmp.code}\n"
            
            # Process other IP protocols
            else:
                self.protocol_stats['Other'] += 1
                output += "  Other IP Protocol\n"
            
            # Add packet size information
            output += f"  Size: {len(packet)} bytes\n"
            
            # Process payload if present
            if packet.haslayer(Raw):
                raw = packet[Raw].load
                # Show first 64 bytes in hex
                output += "  Payload (hex): " + " ".join(f"{x:02x}" for x in raw[:64]) + "\n"
                # Show ASCII representation (printable chars only)
                try:
                    output += "  Payload (ASCII): " + "".join(
                        chr(x) if 32 <= x < 127 else "." for x in raw[:64]) + "\n"
                except:
                    pass
        
        # Write to log file if specified
        if log_file:
            log_file.write(output + "\n")
        # Print to console if verbose mode
        if verbose:
            print(output)
    
    def print_stats(self):
        """Print summary statistics of captured traffic"""
        print("\n=== Sniffer Statistics ===")
        print(f"Total packets captured: {self.packet_count}")
        # Calculate and print protocol percentages
        for proto, count in self.protocol_stats.items():
            if self.packet_count > 0:
                percentage = count/self.packet_count
            else:
                percentage = 0
            print(f"{proto}: {count} packets ({percentage:.1%})")

def main():
    """Main function to handle command-line arguments and start sniffing"""
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Enhanced Network Sniffer")
    # Define command-line arguments
    parser.add_argument("interface", help="Network interface to sniff on")
    parser.add_argument("-o", "--output", help="Output log file (default: sniffer.log)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-f", "--filter", help="BPF filter to apply")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 for unlimited)")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Initialize sniffer
    sniffer = EnhancedSniffer()
    # Open log file if specified
    log_file = open(args.output or "sniffer.log", "a") if args.output else None
    
    try:
        print(f"Starting sniffer on interface {args.interface}")
        print("Press Ctrl+C to stop...\n")
        
        # Prepare sniffing parameters
        sniff_kwargs = {
            'iface': args.interface,  # Interface to sniff
            'prn': lambda pkt: sniffer.handle_packet(pkt, log_file, args.verbose),  # Callback
            'store': 0  # Don't store packets in memory
        }
        
        # Apply BPF filter if specified
        if args.filter:
            sniff_kwargs['filter'] = args.filter
            print(f"Applying filter: {args.filter}")
        
        # Set packet count limit if specified
        if args.count:
            sniff_kwargs['count'] = args.count
        
        # Start sniffing
        sniff(**sniff_kwargs)
        
    except KeyboardInterrupt:
        print("\nStopping sniffer...")
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
    finally:
        # Clean up resources
        if log_file:
            log_file.close()
        # Print statistics
        sniffer.print_stats()

if __name__ == "__main__":
    main()