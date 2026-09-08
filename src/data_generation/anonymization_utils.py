"""
Anonymization utilities for e-Government Portal Protection.
Provides functions for masking PII and validating IPs for synthetic data.
"""

import hashlib
import ipaddress

def hash_pii(value: str, salt: str = "secret_salt_2026") -> str:
    """
    Hash a PII value using SHA-256 with a salt.
    
    Args:
        value (str): The PII string to hash.
        salt (str): The salt to add before hashing.
        
    Returns:
        str: The SHA-256 hex digest.
    """
    if not value:
        return ""
    salted_value = f"{value}{salt}".encode('utf-8')
    return hashlib.sha256(salted_value).hexdigest()

def anonymize_ip(ip: str) -> str:
    """
    Map an IP address to a reserved range (for documentation/synthetic use).
    For simplicity, this function returns a dummy documentation IP if not already one.
    
    Args:
        ip (str): The original IP.
        
    Returns:
        str: Anonymized IP in reserved ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
    """
    if validate_reserved_ip(ip):
        return ip
    # Just a naive hash to documentation IP
    # In a real scenario, maintain a mapping or consistent hash to 192.0.2.x
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    last_octet = (h % 253) + 1
    return f"192.0.2.{last_octet}"

def mask_citizen_id(cid: str) -> str:
    """
    Partially mask a citizen ID. 
    Format CIT-XXXXXX -> CIT-XXX***
    
    Args:
        cid (str): The original citizen ID.
        
    Returns:
        str: The masked citizen ID.
    """
    if not cid or not cid.startswith("CIT-"):
        return cid
    return cid[:7] + "***"

def validate_reserved_ip(ip: str) -> bool:
    """
    Check if an IP address is in approved reserved ranges.
    Allowed ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    
    Args:
        ip (str): The IP address to check.
        
    Returns:
        bool: True if the IP is in an approved reserved range, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        net1 = ipaddress.ip_network("192.0.2.0/24")
        net2 = ipaddress.ip_network("198.51.100.0/24")
        net3 = ipaddress.ip_network("203.0.113.0/24")
        return ip_obj in net1 or ip_obj in net2 or ip_obj in net3
    except ValueError:
        return False
