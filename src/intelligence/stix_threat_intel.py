"""
STIX Threat Intelligence module.
Generates STIX 2.1 bundles and manages Priority Intelligence Requirements (PIRs).
"""

import json
import uuid
import datetime
from typing import List, Dict, Any
import random

NAMESPACE_UUID = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')

def generate_uuid(type_name: str, name: str) -> str:
    """Generate a deterministic UUID based on type and name."""
    return f"{type_name}--{uuid.uuid5(NAMESPACE_UUID, f'{type_name}:{name}')}"

def get_timestamp() -> str:
    return datetime.datetime.utcnow().isoformat() + 'Z'

class ThreatIntelligenceManager:
    """Manager for creating and bundling STIX 2.1 Threat Intel."""
    
    def __init__(self):
        self.objects = []
        random.seed(42)

    def define_priority_intelligence_requirements(self) -> List[Dict[str, str]]:
        """Define PIRs for e-Government portal protection."""
        return [
            {
                "id": "PIR-001",
                "question": "What IP addresses are conducting credential stuffing against citizen authentication endpoints?"
            },
            {
                "id": "PIR-002",
                "question": "Which citizen accounts show signs of unauthorized access or account takeover?"
            },
            {
                "id": "PIR-003",
                "question": "What attack tools and techniques are being used to evade WAF controls?"
            },
            {
                "id": "PIR-004",
                "question": "Which PII datasets are being targeted for exfiltration via API endpoints?"
            },
            {
                "id": "PIR-005",
                "question": "What is the geographic distribution and infrastructure of the attacking botnet?"
            }
        ]

    def create_threat_actor(self, name: str, description: str, sophistication: str, goals: List[str]) -> Dict[str, Any]:
        """Create STIX 2.1 Threat Actor object."""
        return {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": generate_uuid('threat-actor', name),
            "created": get_timestamp(),
            "modified": get_timestamp(),
            "name": name,
            "description": description,
            "sophistication": sophistication,
            "goals": goals
        }

    def create_attack_pattern(self, name: str, description: str, kill_chain_phase: str) -> Dict[str, Any]:
        """Create STIX 2.1 Attack Pattern object."""
        return {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": generate_uuid('attack-pattern', name),
            "created": get_timestamp(),
            "modified": get_timestamp(),
            "name": name,
            "description": description,
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": kill_chain_phase
                }
            ]
        }

    def create_indicator(self, indicator_type: str, pattern: str, description: str, valid_from: str) -> Dict[str, Any]:
        """Create STIX 2.1 Indicator object."""
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": generate_uuid('indicator', pattern),
            "created": get_timestamp(),
            "modified": get_timestamp(),
            "name": f"{indicator_type} Indicator",
            "description": description,
            "indicator_types": [indicator_type],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": valid_from
        }

    def create_observed_data(self, objects_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Create STIX 2.1 Observed Data object."""
        return {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": generate_uuid('observed-data', str(objects_dict)),
            "created": get_timestamp(),
            "modified": get_timestamp(),
            "first_observed": get_timestamp(),
            "last_observed": get_timestamp(),
            "number_observed": 1,
            "objects": objects_dict
        }

    def create_malware(self, name: str, malware_types: List[str], description: str) -> Dict[str, Any]:
        """Create STIX 2.1 Malware object."""
        return {
            "type": "malware",
            "spec_version": "2.1",
            "id": generate_uuid('malware', name),
            "created": get_timestamp(),
            "modified": get_timestamp(),
            "name": name,
            "description": description,
            "malware_types": malware_types,
            "is_family": False
        }

    def create_relationship(self, source_id: str, relationship_type: str, target_id: str) -> Dict[str, Any]:
        """Create STIX 2.1 Relationship object."""
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": generate_uuid('relationship', f"{source_id}-{relationship_type}-{target_id}"),
            "created": get_timestamp(),
            "modified": get_timestamp(),
            "relationship_type": relationship_type,
            "source_ref": source_id,
            "target_ref": target_id
        }

    def build_threat_bundle(self, attacker_ips: List[str], compromised_citizens: List[str], attack_patterns_found: List[str]) -> Dict[str, Any]:
        """Build full STIX 2.1 Bundle based on incident findings."""
        objects = []
        
        # Threat Actor
        ta = self.create_threat_actor(
            name="GovPortal-Botnet-Cluster",
            description="Distributed botnet targeting e-Government portals for credential stuffing and data exfiltration.",
            sophistication="intermediate",
            goals=["credential-theft", "data-theft"]
        )
        objects.append(ta)
        
        # Attack Patterns
        ap_cred = self.create_attack_pattern("Credential Stuffing", "T1110.004", "credential-access")
        ap_brute = self.create_attack_pattern("Brute Force", "T1110", "credential-access")
        ap_api = self.create_attack_pattern("API Abuse", "T1059", "execution")
        ap_exfil = self.create_attack_pattern("Data Exfiltration", "T1041", "exfiltration")
        
        objects.extend([ap_cred, ap_brute, ap_api, ap_exfil])
        
        # Relationships: Threat Actor uses Attack Patterns
        objects.append(self.create_relationship(ta['id'], "uses", ap_cred['id']))
        objects.append(self.create_relationship(ta['id'], "uses", ap_exfil['id']))
        
        # Indicators for IPs
        for ip in attacker_ips[:5]: # Limit for bundle size
            ind = self.create_indicator(
                indicator_type="malicious-activity",
                pattern=f"[ipv4-addr:value = '{ip}']",
                description=f"IP address {ip} observed participating in botnet cluster.",
                valid_from=get_timestamp()
            )
            objects.append(ind)
            objects.append(self.create_relationship(ind['id'], "indicates", ta['id']))
            
        # Create Bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }
        return bundle

    def enrich_with_reputation(self, ip_list: List[str]) -> Dict[str, Dict[str, Any]]:
        """Simulate IP reputation enrichment."""
        reputation = {}
        categories = ['botnet', 'scanner', 'proxy', 'tor_node']
        for ip in ip_list:
            reputation[ip] = {
                "threat_score": random.randint(60, 100),
                "category": random.choice(categories),
                "country": "Unknown", # Would use geoip in real life
                "asn": f"AS{random.randint(1000, 99999)}",
                "first_seen": (datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(1, 30))).isoformat() + 'Z',
                "last_seen": get_timestamp()
            }
        return reputation

    def generate_operational_intel_card(self, threat_bundle: Dict[str, Any]) -> str:
        """Generate formatted string for SOC analysts."""
        card = "# Operational Intelligence Card\n\n"
        
        ta_name = "Unknown"
        indicators = []
        for obj in threat_bundle.get("objects", []):
            if obj["type"] == "threat-actor":
                ta_name = obj["name"]
            elif obj["type"] == "indicator":
                indicators.append(obj["pattern"])
                
        card += f"**Threat Actor:** {ta_name}\n\n"
        card += "**Indicators of Compromise (IOCs):**\n"
        for ind in indicators:
            card += f"- {ind}\n"
            
        card += "\n**Recommended Actions:**\n"
        card += "1. Deploy indicators to WAF blocklists.\n"
        card += "2. Search SIEM for historical connections to these IPs.\n"
        card += "3. Monitor targeted API endpoints for anomalous payload sizes.\n"
        
        return card

    def generate_executive_summary(self, threat_bundle: Dict[str, Any], affected_count: int, risk_level: str) -> str:
        """Generate formatted string for CISO/DPO audience."""
        summary = "# Threat Intelligence Executive Summary\n\n"
        summary += f"**Risk Level:** {risk_level.upper()}\n"
        summary += f"**Affected Citizens:** {affected_count}\n\n"
        
        ta_desc = ""
        for obj in threat_bundle.get("objects", []):
            if obj["type"] == "threat-actor":
                ta_desc = obj.get("description", "")
                
        summary += "**Threat Actor Profile:**\n"
        summary += f"{ta_desc}\n\n"
        
        summary += "**Impact Assessment:**\n"
        summary += "The threat actor successfully leveraged credential stuffing techniques to compromise citizen accounts, followed by unauthorized access to PII via API endpoints.\n\n"
        
        summary += "**Strategic Recommendations:**\n"
        summary += "1. Implement mandatory Multi-Factor Authentication (MFA) for all citizen accounts.\n"
        summary += "2. Enhance WAF capabilities with behavioral analysis to detect automated scraping.\n"
        summary += "3. Conduct a comprehensive review of API rate limits and payload restrictions.\n"
        
        return summary

    def export_stix_bundle(self, bundle: Dict[str, Any], output_path: str) -> None:
        """Save STIX bundle as JSON."""
        with open(output_path, 'w') as f:
            json.dump(bundle, f, indent=2)

    def export_pir_report(self, pirs: List[Dict[str, str]], evidence: Dict[str, str], output_path: str) -> None:
        """Save PIR assessment."""
        report = []
        for pir in pirs:
            report.append({
                "pir_id": pir["id"],
                "question": pir["question"],
                "assessment": evidence.get(pir["id"], "No evidence collected.")
            })
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

if __name__ == '__main__':
    import os
    import pandas as pd
    
    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    RAW_DIR = os.path.join(PROJECT_ROOT, 'data', 'raw')
    PROCESSED_DIR = os.path.join(PROJECT_ROOT, 'data', 'processed')
    
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    
    auth_df = pd.read_csv(os.path.join(RAW_DIR, 'auth_db_audit_logs.csv'))
    
    attacker_ips = auth_df[auth_df['src_ip'].str.startswith('198.51.100.') | auth_df['src_ip'].str.startswith('203.0.113.')]['src_ip'].unique().tolist()
    if 'is_impossible_travel' in auth_df.columns:
        compromised_citizens = auth_df[auth_df['is_impossible_travel'] == 1]['citizen_id'].dropna().unique().tolist()
    else:
        compromised_citizens = []
    
    manager = ThreatIntelligenceManager()
    
    pirs = manager.define_priority_intelligence_requirements()
    threat_bundle = manager.build_threat_bundle(attacker_ips, compromised_citizens, ["T1110.004", "T1041"])
    ip_reputation = manager.enrich_with_reputation(attacker_ips)
    
    op_intel = manager.generate_operational_intel_card(threat_bundle)
    exec_summary = manager.generate_executive_summary(threat_bundle, len(compromised_citizens), "CRITICAL")
    
    manager.export_stix_bundle(threat_bundle, os.path.join(PROCESSED_DIR, 'stix_bundle.json'))
    
    pir_report = {
        'pirs': pirs,
        'operational_intel_card': op_intel,
        'executive_summary': exec_summary,
        'ip_reputation': [{'ip': k, **v} for k, v in ip_reputation.items()],
        'total_indicators': sum(1 for obj in threat_bundle.get('objects', []) if obj['type'] == 'indicator'),
        'threat_actor_name': next((obj['name'] for obj in threat_bundle.get('objects', []) if obj['type'] == 'threat-actor'), 'Unknown')
    }
    
    with open(os.path.join(PROCESSED_DIR, 'pir_report.json'), 'w') as f:
        json.dump(pir_report, f, indent=2)
        
    print(f"STIX Threat Intel Complete. Generated bundle with {pir_report['total_indicators']} indicators.")
