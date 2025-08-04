#!/usr/bin/env python3
"""
DNS Tunnel Detection and Analysis Module
---------------------------------------
Detects and analyzes potential DNS tunneling activities in network traffic.
Uses statistical analysis and pattern matching to identify suspicious DNS queries.
"""

import os
import sys
import json
import time
import socket
import struct
import random
import argparse
import subprocess
import ipaddress
from datetime import datetime
from collections import defaultdict, Counter
from colorama import Fore, Style, init
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
from scapy.all import *

# Initialize colorama
init(autoreset=True)

class DNSTunnelDetector:
    def __init__(self, interface=None, pcap_file=None, domain=None):
        """Initialize the DNS tunnel detector."""
        self.interface = interface
        self.pcap_file = pcap_file
        self.domain = domain
        self.suspicious_queries = []
        self.stats = {
            'total_packets': 0,
            'dns_packets': 0,
            'suspicious_queries': 0,
            'domains': defaultdict(int),
            'query_types': defaultdict(int),
            'clients': defaultdict(int)
        }
        
        # Known DNS tunneling tools and patterns
        self.tunnel_patterns = {
            'iodine': ['.+\.t\.', '^[a-z0-9]{16,}\\.'],
            'dnscat2': ['^[a-f0-9]{16,}\\.', '^[a-z0-9]{32,}\\.'],
            'dns2tcp': ['^[a-f0-9]{16,}\\.', '^[a-z0-9]{20,}\\.'],
            'tuns': ['^[a-f0-9]{16,}\\.', '^[a-z0-9]{24,}\\.'],
            'heyoka': ['^[a-f0-9]{32,}\\.'],
            'iodine-http': ['^[a-z0-9]{20,}\\.', '^[a-f0-9]{40,}\\.']
        }
        
        # Known DNS tunneling domains
        self.known_tunnel_domains = [
            't1.dnslog.cn', 'dnslog.link', 'dnslog.pw', 'ceye.io',
            'burpcollaborator.net', 'interact.sh', 'dnslog.site',
            'dnslog.pro', 'dnslog.co', 'dnslog.me', 'dnslog.xyz',
            'dnslog.rst.im', 'dnslog.hacking8.com', 'dnslog.h4ck.fun'
        ]
        
        # Thresholds for detection
        self.thresholds = {
            'max_query_length': 50,  # Max normal query length
            'max_subdomains': 5,     # Max subdomains in a minute
            'max_entropy': 4.5,      # Maximum entropy for domain
            'min_packet_size': 100,  # Minimum packet size to consider
            'max_domains_per_client': 20  # Max unique domains per client
        }
    
    def calculate_entropy(self, data):
        """Calculate the Shannon entropy of a string."""
        if not data:
            return 0
        
        entropy = 0
        for x in (data.count(c) / len(data) for c in set(data)):
            entropy -= x * (x and math.log(x, 2))
        return entropy
    
    def is_suspicious_domain(self, domain):
        """Check if a domain matches known DNS tunneling patterns."""
        if not domain:
            return False
            
        # Check against known tunnel domains
        if any(tunnel_domain in domain for tunnel_domain in self.known_tunnel_domains):
            return True
        
        # Check domain length
        if len(domain) > self.thresholds['max_query_length']:
            return True
        
        # Check entropy
        entropy = self.calculate_entropy(domain)
        if entropy > self.thresholds['max_entropy']:
            return True
            
        # Check for known tunnel patterns
        for tool, patterns in self.tunnel_patterns.items():
            if any(re.search(pattern, domain) for pattern in patterns):
                return True
                
        return False
    
    def analyze_packet(self, packet):
        """Analyze a single network packet for DNS tunneling indicators."""
        self.stats['total_packets'] += 1
        
        # Check if it's a DNS packet
        if not packet.haslayer(DNS):
            return
            
        self.stats['dns_packets'] += 1
        dns_layer = packet[DNS]
        
        # Check if it's a query (not a response)
        if not dns_layer.qr:
            query = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            query_type = dns_layer.qd.qtype
            
            # Update stats
            self.stats['query_types'][query_type] += 1
            self.stats['domains'][query] += 1
            
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                self.stats['clients'][src_ip] += 1
                
                # Check for suspicious domain patterns
                if self.is_suspicious_domain(query):
                    self.stats['suspicious_queries'] += 1
                    self.suspicious_queries.append({
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': src_ip,
                        'query': query,
                        'query_type': query_type,
                        'packet_size': len(packet),
                        'entropy': self.calculate_entropy(query)
                    })
    
    def capture_live_traffic(self, timeout=60):
        """Capture and analyze live DNS traffic."""
        print(f"{Fore.CYAN}[*] Starting live capture on interface {self.interface}...{Style.RESET}")
        try:
            sniff(iface=self.interface, 
                 filter="udp port 53", 
                 prn=self.analyze_packet, 
                 store=0,
                 timeout=timeout)
        except Exception as e:
            print(f"{Fore.RED}[!] Error capturing traffic: {e}{Style.RESET}")
    
    def analyze_pcap(self):
        """Analyze DNS traffic from a PCAP file."""
        print(f"{Fore.CYAN}[*] Analyzing PCAP file: {self.pcap_file}{Style.RESET}")
        try:
            sniff(offline=self.pcap_file, 
                 filter="udp port 53", 
                 prn=self.analyze_packet, 
                 store=0)
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing PCAP: {e}{Style.RESET}")
    
    def check_domain(self, domain):
        """Check a specific domain for DNS tunneling indicators."""
        print(f"{Fore.CYAN}[*] Analyzing domain: {domain}{Style.RESET}")
        
        results = {
            'domain': domain,
            'is_suspicious': False,
            'indicators': [],
            'entropy': self.calculate_entropy(domain),
            'length': len(domain),
            'subdomains': len(domain.split('.')) - 1
        }
        
        # Check domain length
        if results['length'] > self.thresholds['max_query_length']:
            results['indicators'].append({
                'type': 'domain_length',
                'severity': 'high',
                'message': f"Domain is too long ({results['length']} chars)"
            })
            results['is_suspicious'] = True
        
        # Check entropy
        if results['entropy'] > self.thresholds['max_entropy']:
            results['indicators'].append({
                'type': 'high_entropy',
                'severity': 'medium',
                'message': f"High entropy detected ({results['entropy']:.2f})"
            })
            results['is_suspicious'] = True
        
        # Check for known tunnel patterns
        for tool, patterns in self.tunnel_patterns.items():
            for pattern in patterns:
                if re.search(pattern, domain):
                    results['indicators'].append({
                        'type': 'tunnel_pattern',
                        'severity': 'high',
                        'message': f"Matches {tool} tunneling pattern: {pattern}"
                    })
                    results['is_suspicious'] = True
        
        # Check against known tunnel domains
        for tunnel_domain in self.known_tunnel_domains:
            if tunnel_domain in domain:
                results['indicators'].append({
                    'type': 'known_tunnel_domain',
                    'severity': 'critical',
                    'message': f"Matches known tunnel domain: {tunnel_domain}"
                })
                results['is_suspicious'] = True
        
        return results
    
    def generate_report(self):
        """Generate a report of the analysis."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'stats': dict(self.stats),
            'suspicious_queries': self.suspicious_queries,
            'top_domains': dict(Counter(self.stats['domains']).most_common(10)),
            'top_clients': dict(Counter(self.stats['clients']).most_common(10)),
            'detection_metrics': {
                'suspicious_ratio': (self.stats['suspicious_queries'] / self.stats['dns_packets'] * 100) 
                                    if self.stats['dns_packets'] > 0 else 0,
                'avg_queries_per_client': (sum(self.stats['clients'].values()) / len(self.stats['clients'])) 
                                          if self.stats['clients'] else 0
            }
        }
        return report

def print_domain_analysis(results):
    """Print domain analysis results in a formatted way."""
    domain = results['domain']
    print(f"\n{Fore.CYAN}=== Domain Analysis ==={Style.RESET}")
    print(f"{Fore.YELLOW}Domain:{Style.RESET} {domain}")
    print(f"{Fore.YELLOW}Length:{Style.RESET} {results['length']} characters")
    print(f"{Fore.YELLOW}Entropy:{Style.RESET} {results['entropy']:.2f}")
    print(f"{Fore.YELLOW}Subdomains:{Style.RESET} {results['subdomains']}")
    
    if results['is_suspicious']:
        print(f"{Fore.RED}⚠ This domain shows signs of DNS tunneling!{Style.RESET}")
        print(f"{Fore.YELLOW}Indicators:{Style.RESET}")
        for indicator in results['indicators']:
            severity_color = {
                'critical': Fore.RED,
                'high': Fore.RED,
                'medium': Fore.YELLOW,
                'low': Fore.BLUE
            }.get(indicator['severity'].lower(), Fore.WHITE)
            
            print(f"  {severity_color}[{indicator['severity'].upper()}]{Style.RESET} {indicator['message']}")
    else:
        print(f"{Fore.GREEN}✓ No clear indicators of DNS tunneling detected.{Style.RESET}")

def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(description='DNS Tunnel Detection Tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--interface', help='Network interface to monitor')
    group.add_argument('-r', '--pcap', help='PCAP file to analyze')
    group.add_argument('-d', '--domain', help='Domain to analyze')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-t', '--timeout', type=int, default=60, 
                       help='Capture timeout in seconds (default: 60)')
    
    args = parser.parse_args()
    
    detector = DNSTunnelDetector(
        interface=args.interface,
        pcap_file=args.pcap,
        domain=args.domain
    )
    
    if args.domain:
        results = detector.check_domain(args.domain)
        print_domain_analysis(results)
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
    else:
        if args.pcap:
            detector.analyze_pcap()
        else:
            detector.capture_live_traffic(timeout=args.timeout)
        
        report = detector.generate_report()
        
        # Print summary
        print(f"\n{Fore.CYAN}=== Analysis Summary ==={Style.RESET}")
        print(f"{Fore.YELLOW}Total packets:{Style.RESET} {report['stats']['total_packets']}")
        print(f"{Fore.YELLOW}DNS packets:{Style.RESET} {report['stats']['dns_packets']}")
        print(f"{Fore.YELLOW}Suspicious queries:{Style.RESET} {report['stats']['suspicious_queries']}")
        print(f"{Fore.YELLOW}Unique domains:{Style.RESET} {len(report['stats']['domains'])}")
        print(f"{Fore.YELLOW}Unique clients:{Style.RESET} {len(report['stats']['clients'])}")
        
        if report['suspicious_queries']:
            print(f"\n{Fore.RED}⚠ Potential DNS tunneling activity detected!{Style.RESET}")
            print(f"{Fore.YELLOW}Suspicious queries:{Style.RESET}")
            for query in report['suspicious_queries'][:5]:  # Show top 5
                print(f"  - {query['source_ip']}: {query['query']} (Type: {query['query_type']})")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n{Fore.GREEN}Report saved to {args.output}{Style.RESET}")

if __name__ == "__main__":
    main()
