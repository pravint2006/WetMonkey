#!/usr/bin/env python3
"""
GeoIP Anomaly Detection Module
-------------------------------
Detects and analyzes potential geographical anomalies in network traffic.
Uses MaxMind GeoLite2 and other techniques to identify suspicious patterns.
"""

import os
import sys
import json
import socket
import requests
import whois
import ipaddress
from datetime import datetime
from colorama import Fore, Style, init
import geoip2.database
from geoip2.errors import AddressNotFoundError

# Initialize colorama
init(autoreset=True)

class GeoIPAnalyzer:
    def __init__(self, db_path=None):
        """Initialize the GeoIP analyzer with optional custom database path."""
        self.db_path = db_path or self._get_default_db_path()
        self.reader = None
        self._initialize_geoip()
        
    def _get_default_db_path(self):
        """Get the default path for GeoLite2 database."""
        return os.path.join(os.path.dirname(__file__), 'GeoLite2-City.mmdb')
    
    def _initialize_geoip(self):
        """Initialize the GeoIP2 database reader."""
        if not os.path.exists(self.db_path):
            print(f"{Fore.YELLOW}Warning: GeoLite2 database not found at {self.db_path}")
            print(f"Please download it from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
            print(f"and place it in: {os.path.dirname(self.db_path)}{Style.RESET_ALL}")
            return False
            
        try:
            self.reader = geoip2.database.Reader(self.db_path)
            return True
        except Exception as e:
            print(f"{Fore.RED}Error initializing GeoIP database: {e}{Style.RESET_ALL}")
            return False
    
    def get_ip_info(self, ip):
        """Get detailed GeoIP information for an IP address."""
        if not self.reader:
            return None
            
        try:
            response = self.reader.city(ip)
            return {
                'ip': ip,
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'postal': response.postal.code,
                'location': {
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'time_zone': response.location.time_zone,
                    'accuracy_radius': response.location.accuracy_radius
                },
                'asn': self._get_asn_info(ip),
                'whois': self._get_whois_info(ip),
                'is_private': ipaddress.ip_address(ip).is_private,
                'is_reserved': ipaddress.ip_address(ip).is_private,
                'timestamp': datetime.utcnow().isoformat()
            }
        except AddressNotFoundError:
            return {'ip': ip, 'error': 'Address not found in database'}
        except Exception as e:
            return {'ip': ip, 'error': str(e)}
    
    def _get_asn_info(self, ip):
        """Get ASN information for an IP address."""
        try:
            asn_db_path = os.path.join(os.path.dirname(__file__), 'GeoLite2-ASN.mmdb')
            if os.path.exists(asn_db_path):
                with geoip2.database.Reader(asn_db_path) as reader:
                    response = reader.asn(ip)
                    return {
                        'asn': response.autonomous_system_number,
                        'organization': response.autonomous_system_organization,
                        'network': str(response.network)
                    }
        except Exception:
            pass
        return None
    
    def _get_whois_info(self, ip):
        """Get WHOIS information for an IP address."""
        try:
            w = whois.whois(ip)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': list(w.name_servers) if w.name_servers else [],
                'status': w.status,
                'emails': w.emails if hasattr(w, 'emails') else None,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'country': w.country,
                'zipcode': w.zipcode
            }
        except Exception as e:
            return {'error': str(e)}
    
    def detect_anomalies(self, ip_info_list):
        """Detect potential anomalies in a list of IP information."""
        if not ip_info_list:
            return []
            
        anomalies = []
        
        # Check for private IPs in public traffic
        for ip_info in ip_info_list:
            if ip_info.get('is_private', False):
                anomalies.append({
                    'type': 'private_ip_in_public_traffic',
                    'ip': ip_info['ip'],
                    'severity': 'high',
                    'description': 'Private IP address detected in what appears to be public traffic'
                })
        
        # Check for unusual geolocation patterns
        countries = [ip.get('country_code') for ip in ip_info_list if ip.get('country_code')]
        if countries:
            from collections import Counter
            country_counts = Counter(countries)
            if len(country_counts) > 5:  # More than 5 different countries
                anomalies.append({
                    'type': 'high_geographical_diversity',
                    'severity': 'medium',
                    'description': f'Traffic from {len(country_counts)} different countries detected',
                    'countries': dict(country_counts)
                })
            
            # Check for traffic from high-risk countries
            high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'SY']  # Example list
            risky_countries = [c for c in high_risk_countries if c in country_counts]
            if risky_countries:
                anomalies.append({
                    'type': 'traffic_from_high_risk_country',
                    'severity': 'high',
                    'description': f'Traffic detected from high-risk countries: {", ".join(risky_countries)}',
                    'countries': {k: v for k, v in country_counts.items() if k in risky_countries}
                })
        
        return anomalies
    
    def spoof_geoip(self, target_url, spoof_ip, headers=None):
        """Spoof GeoIP by sending requests with custom headers."""
        try:
            headers = headers or {}
            headers.update({
                'X-Forwarded-For': spoof_ip,
                'X-Real-IP': spoof_ip,
                'X-Client-IP': spoof_ip,
                'X-Remote-IP': spoof_ip,
                'X-Remote-Addr': spoof_ip,
                'X-Originating-IP': spoof_ip,
                'X-Host': spoof_ip,
                'X-Forwarded': spoof_ip,
                'Forwarded-For': spoof_ip,
                'Forwarded': f'for={spoof_ip}'
            })
            
            response = requests.get(target_url, headers=headers, timeout=10)
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'spoofed_ip': spoof_ip,
                'target_url': target_url,
                'success': True
            }
        except Exception as e:
            return {
                'error': str(e),
                'spoofed_ip': spoof_ip,
                'target_url': target_url,
                'success': False
            }

def print_ip_info(ip_info):
    """Print IP information in a formatted way."""
    if not ip_info or 'error' in ip_info:
        print(f"{Fore.RED}Error: {ip_info.get('error', 'Unknown error')}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}=== IP Information ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}IP Address:{Style.RESET_ALL} {ip_info['ip']}")
    
    if 'country' in ip_info:
        print(f"{Fore.YELLOW}Location:{Style.RESET_ALL} {ip_info.get('city', 'Unknown')}, "
              f"{ip_info.get('country', 'Unknown')} ({ip_info.get('country_code', '??')})")
    
    if 'location' in ip_info:
        loc = ip_info['location']
        print(f"{Fore.YELLOW}Coordinates:{Style.RESET_ALL} {loc.get('latitude', '?')}, {loc.get('longitude', '?')}")
        print(f"{Fore.YELLOW}Time Zone:{Style.RESET_ALL} {loc.get('time_zone', 'Unknown')}")
    
    if 'asn' in ip_info and ip_info['asn']:
        print(f"{Fore.YELLOW}ASN:{Style.RESET_ALL} {ip_info['asn'].get('asn', '?')} - "
              f"{ip_info['asn'].get('organization', 'Unknown')}")
        print(f"{Fore.YELLOW}Network:{Style.RESET_ALL} {ip_info['asn'].get('network', 'Unknown')}")
    
    if 'whois' in ip_info and ip_info['whois'] and not isinstance(ip_info['whois'], dict):
        print(f"{Fore.YELLOW}Organization:{Style.RESET_ALL} {ip_info['whois'].get('org', 'Unknown')}")
        print(f"{Fore.YELLOW}Registrar:{Style.RESET_ALL} {ip_info['whois'].get('registrar', 'Unknown')}")
    
    if ip_info.get('is_private', False):
        print(f"{Fore.RED}⚠ This is a private IP address{Style.RESET_ALL}")
    elif ip_info.get('is_reserved', False):
        print(f"{Fore.YELLOW}⚠ This is a reserved IP address{Style.RESET_ALL}")

def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='GeoIP Anomaly Detection Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Lookup command
    lookup_parser = subparsers.add_parser('lookup', help='Lookup IP information')
    lookup_parser.add_argument('ip', help='IP address to look up')
    
    # Spoof command
    spoof_parser = subparsers.add_parser('spoof', help='Spoof GeoIP')
    spoof_parser.add_argument('url', help='Target URL')
    spoof_parser.add_argument('--ip', required=True, help='IP to spoof')
    spoof_parser.add_argument('--header', action='append', help='Additional headers (key:value)')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze IPs for anomalies')
    analyze_parser.add_argument('ips', nargs='+', help='IP addresses to analyze')
    
    args = parser.parse_args()
    
    analyzer = GeoIPAnalyzer()
    
    if args.command == 'lookup':
        ip_info = analyzer.get_ip_info(args.ip)
        print_ip_info(ip_info)
    
    elif args.command == 'spoof':
        headers = {}
        if args.header:
            for h in args.header:
                if ':' in h:
                    k, v = h.split(':', 1)
                    headers[k.strip()] = v.strip()
        
        result = analyzer.spoof_geoip(args.url, args.ip, headers)
        if result['success']:
            print(f"{Fore.GREEN}Request successful! Status code: {result['status_code']}{Style.RESET_ALL}")
            print(f"Spoofed IP: {result['spoofed_ip']}")
            print(f"Target URL: {result['target_url']}")
        else:
            print(f"{Fore.RED}Error: {result.get('error', 'Unknown error')}{Style.RESET_ALL}")
    
    elif args.command == 'analyze':
        ip_infos = [analyzer.get_ip_info(ip) for ip in args.ips]
        anomalies = analyzer.detect_anomalies(ip_infos)
        
        print(f"\n{Fore.CYAN}=== Analysis Results ==={Style.RESET_ALL}")
        print(f"Analyzed {len(ip_infos)} IP addresses")
        
        if anomalies:
            print(f"\n{Fore.RED}⚠ Detected {len(anomalies)} potential anomalies:{Style.RESET_ALL}")
            for i, anomaly in enumerate(anomalies, 1):
                print(f"\n{Fore.YELLOW}{i}. {anomaly['type'].replace('_', ' ').title()}{Style.RESET_ALL}")
                print(f"   Severity: {anomaly['severity'].title()}")
                print(f"   Description: {anomaly['description']}")
                if 'countries' in anomaly:
                    print("   Countries:")
                    for country, count in anomaly['countries'].items():
                        print(f"     - {country}: {count} IPs")
        else:
            print(f"{Fore.GREEN}No significant anomalies detected.{Style.RESET_ALL}")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
