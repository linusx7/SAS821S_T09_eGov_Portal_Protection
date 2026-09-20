"""
Incident Correlation Engine module.
Reconstructs multi-stage attack timelines by correlating events across log sources.
"""

import pandas as pd
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import json
import datetime
import matplotlib.pyplot as plt

@dataclass
class AttackPhase:
    """Represents a specific phase in the attack lifecycle."""
    name: str
    description: str
    start_time: pd.Timestamp
    end_time: pd.Timestamp
    involved_ips: List[str]
    affected_citizens: List[str]
    event_ids: List[str]

@dataclass
class TimelineEvent:
    """Represents a single event in the attack timeline."""
    event_id: str
    timestamp: pd.Timestamp
    source: str
    phase: str
    description: str
    severity: str
    related_entities: Dict[str, Any]

class IncidentCorrelationEngine:
    """Engine to correlate events across log sources and reconstruct attack timelines."""
    
    def __init__(self):
        self.waf_df = pd.DataFrame()
        self.api_df = pd.DataFrame()
        self.auth_df = pd.DataFrame()
        self.complaints_df = pd.DataFrame()
        
        self.attack_phases: List[AttackPhase] = []
        self.timeline: List[TimelineEvent] = []
        
        self.compromised_citizens: set = set()
        self.attacker_ips: set = set()

    def load_all_sources(self, waf_df: pd.DataFrame, api_df: pd.DataFrame, auth_df: pd.DataFrame, complaints_df: pd.DataFrame) -> None:
        """Load all telemetry sources."""
        self.waf_df = waf_df.copy()
        self.api_df = api_df.copy()
        self.auth_df = auth_df.copy()
        self.complaints_df = complaints_df.copy()
        
        # Ensure timestamp columns are datetime
        for df in [self.waf_df, self.api_df, self.auth_df, self.complaints_df]:
            if not df.empty and 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])

    def identify_attack_phases(self) -> List[AttackPhase]:
        """Detect and identify attack phases from correlated data."""
        phases = []
        
        # 1. RECONNAISSANCE: High 404/403 rate from same IP targeting admin/config paths
        if not self.waf_df.empty:
            recon_events = self.waf_df[
                (self.waf_df['status_code'].isin([403, 404])) & 
                (self.waf_df['url_path'].str.contains('admin|config|.env', case=False, na=False))
            ]
            if not recon_events.empty:
                ips = recon_events['src_ip'].unique().tolist()
                self.attacker_ips.update(ips)
                phases.append(AttackPhase(
                    name="RECONNAISSANCE",
                    description="High 404/403 rate targeting admin/config paths",
                    start_time=recon_events['timestamp'].min(),
                    end_time=recon_events['timestamp'].max(),
                    involved_ips=ips,
                    affected_citizens=[],
                    event_ids=recon_events['event_id'].tolist()
                ))

        # 2. CREDENTIAL_STUFFING: High volume LOGIN_FAILED events
        if not self.auth_df.empty:
            cred_events = self.auth_df[self.auth_df['auth_event'] == 'LOGIN_FAILED']
            if not cred_events.empty:
                # Group by IP and count
                ip_counts = cred_events['src_ip'].value_counts()
                bad_ips = ip_counts[ip_counts > 10].index.tolist() # Arbitrary threshold
                if bad_ips:
                    bad_events = cred_events[cred_events['src_ip'].isin(bad_ips)]
                    self.attacker_ips.update(bad_ips)
                    phases.append(AttackPhase(
                        name="CREDENTIAL_STUFFING",
                        description="High volume LOGIN_FAILED events from distributed IPs",
                        start_time=bad_events['timestamp'].min(),
                        end_time=bad_events['timestamp'].max(),
                        involved_ips=bad_ips,
                        affected_citizens=bad_events['citizen_id'].dropna().unique().tolist(),
                        event_ids=bad_events['event_id'].tolist()
                    ))

        # 3. ACCOUNT_TAKEOVER: LOGIN_SUCCESS with impossible travel or attacker IPs
        if not self.auth_df.empty:
            ato_events = self.auth_df[
                (self.auth_df['auth_event'] == 'LOGIN_SUCCESS') & 
                ((self.auth_df['is_impossible_travel'] == True) | (self.auth_df['src_ip'].isin(self.attacker_ips)))
            ]
            if not ato_events.empty:
                ips = ato_events['src_ip'].unique().tolist()
                citizens = ato_events['citizen_id'].unique().tolist()
                self.attacker_ips.update(ips)
                self.compromised_citizens.update(citizens)
                phases.append(AttackPhase(
                    name="ACCOUNT_TAKEOVER",
                    description="Successful logins with impossible travel or known attacker IPs",
                    start_time=ato_events['timestamp'].min(),
                    end_time=ato_events['timestamp'].max(),
                    involved_ips=ips,
                    affected_citizens=citizens,
                    event_ids=ato_events['event_id'].tolist()
                ))

        # 4. DATA_EXFILTRATION: High-volume API calls to PII endpoints
        if not self.api_df.empty:
            exfil_events = self.api_df[
                (self.api_df['endpoint'].str.contains('/tax/records|/civil/registry', case=False, na=False)) &
                (self.api_df['response_time_ms'] > 1000) # Proxy for large payloads
            ]
            if not exfil_events.empty:
                ips = exfil_events['src_ip'].unique().tolist()
                citizens = exfil_events['citizen_id'].dropna().unique().tolist()
                self.attacker_ips.update(ips)
                self.compromised_citizens.update(citizens)
                phases.append(AttackPhase(
                    name="DATA_EXFILTRATION",
                    description="High-volume API calls to PII endpoints",
                    start_time=exfil_events['timestamp'].min(),
                    end_time=exfil_events['timestamp'].max(),
                    involved_ips=ips,
                    affected_citizens=citizens,
                    event_ids=exfil_events['event_id'].tolist()
                ))

        # 5. DB_EXFILTRATION: Large SELECT queries
        if not self.auth_df.empty:
            db_exfil = self.auth_df[
                (self.auth_df['db_query'].str.contains('SELECT', case=False, na=False)) &
                (self.auth_df['rows_returned'] > 1000)
            ]
            if not db_exfil.empty:
                ips = db_exfil['src_ip'].unique().tolist()
                citizens = db_exfil['citizen_id'].dropna().unique().tolist()
                self.attacker_ips.update(ips)
                self.compromised_citizens.update(citizens)
                phases.append(AttackPhase(
                    name="DB_EXFILTRATION",
                    description="Large SELECT queries from compromised sessions",
                    start_time=db_exfil['timestamp'].min(),
                    end_time=db_exfil['timestamp'].max(),
                    involved_ips=ips,
                    affected_citizens=citizens,
                    event_ids=db_exfil['event_id'].tolist()
                ))

        # 6. CITIZEN_IMPACT: Complaint tickets correlated to compromised citizen_ids
        if not self.complaints_df.empty and self.compromised_citizens:
            impact_events = self.complaints_df[self.complaints_df['citizen_id'].isin(self.compromised_citizens)]
            if not impact_events.empty:
                phases.append(AttackPhase(
                    name="CITIZEN_IMPACT",
                    description="Complaint tickets from compromised citizens",
                    start_time=impact_events['timestamp'].min(),
                    end_time=impact_events['timestamp'].max(),
                    involved_ips=[],
                    affected_citizens=impact_events['citizen_id'].unique().tolist(),
                    event_ids=impact_events['ticket_id'].tolist()
                ))

        self.attack_phases = phases
        return phases

    def build_timeline(self) -> List[TimelineEvent]:
        """Construct the full attack timeline."""
        events = []
        
        # We assume identify_attack_phases has been run
        for phase in self.attack_phases:
            # Reconstruct events based on phase
            # For simplicity, we create one summary event per phase or map original events
            # Here we just map the original events for a few sample cases to avoid massive timelines
            
            # Recon events
            if phase.name == "RECONNAISSANCE" and not self.waf_df.empty:
                df = self.waf_df[self.waf_df['event_id'].isin(phase.event_ids)]
                for _, row in df.iterrows():
                    events.append(TimelineEvent(
                        event_id=row['event_id'],
                        timestamp=row['timestamp'],
                        source='WAF',
                        phase=phase.name,
                        description=f"Recon action: {row['http_method']} {row['url_path']} ({row['status_code']})",
                        severity='LOW',
                        related_entities={'ip': row['src_ip']}
                    ))
                    
            elif phase.name == "CREDENTIAL_STUFFING" and not self.auth_df.empty:
                df = self.auth_df[self.auth_df['event_id'].isin(phase.event_ids)].head(50) # Limit for timeline
                for _, row in df.iterrows():
                    events.append(TimelineEvent(
                        event_id=row['event_id'],
                        timestamp=row['timestamp'],
                        source='AUTH',
                        phase=phase.name,
                        description=f"Failed login attempt for {row.get('citizen_id', 'Unknown')}",
                        severity='MEDIUM',
                        related_entities={'ip': row['src_ip'], 'citizen_id': row.get('citizen_id')}
                    ))
                    
            elif phase.name == "ACCOUNT_TAKEOVER" and not self.auth_df.empty:
                df = self.auth_df[self.auth_df['event_id'].isin(phase.event_ids)]
                for _, row in df.iterrows():
                    events.append(TimelineEvent(
                        event_id=row['event_id'],
                        timestamp=row['timestamp'],
                        source='AUTH',
                        phase=phase.name,
                        description=f"Account takeover for {row.get('citizen_id', 'Unknown')}",
                        severity='HIGH',
                        related_entities={'ip': row['src_ip'], 'citizen_id': row.get('citizen_id')}
                    ))
                    
            elif phase.name == "DATA_EXFILTRATION" and not self.api_df.empty:
                df = self.api_df[self.api_df['event_id'].isin(phase.event_ids)]
                for _, row in df.iterrows():
                    events.append(TimelineEvent(
                        event_id=row['event_id'],
                        timestamp=row['timestamp'],
                        source='API',
                        phase=phase.name,
                        description=f"Data exfiltration from {row.get('endpoint', 'Unknown')}",
                        severity='CRITICAL',
                        related_entities={'ip': row['src_ip'], 'citizen_id': row.get('citizen_id')}
                    ))
                    
            elif phase.name == "CITIZEN_IMPACT" and not self.complaints_df.empty:
                df = self.complaints_df[self.complaints_df['ticket_id'].isin(phase.event_ids)]
                for _, row in df.iterrows():
                    events.append(TimelineEvent(
                        event_id=row['ticket_id'],
                        timestamp=row['timestamp'],
                        source='COMPLAINTS',
                        phase=phase.name,
                        description=f"Citizen complaint: {row.get('category', 'Unknown')}",
                        severity='HIGH',
                        related_entities={'citizen_id': row.get('citizen_id')}
                    ))
                    
        events.sort(key=lambda x: x.timestamp)
        self.timeline = events
        return events

    def correlate_entities(self, entity_type: str, entity_value: str) -> Dict[str, pd.DataFrame]:
        """Find all events involving this IP/citizen_id across all sources."""
        results = {}
        if entity_type == 'ip':
            if not self.waf_df.empty and 'src_ip' in self.waf_df.columns:
                results['waf'] = self.waf_df[self.waf_df['src_ip'] == entity_value]
            if not self.api_df.empty and 'src_ip' in self.api_df.columns:
                results['api'] = self.api_df[self.api_df['src_ip'] == entity_value]
            if not self.auth_df.empty and 'src_ip' in self.auth_df.columns:
                results['auth'] = self.auth_df[self.auth_df['src_ip'] == entity_value]
        elif entity_type == 'citizen_id':
            if not self.api_df.empty and 'citizen_id' in self.api_df.columns:
                results['api'] = self.api_df[self.api_df['citizen_id'] == entity_value]
            if not self.auth_df.empty and 'citizen_id' in self.auth_df.columns:
                results['auth'] = self.auth_df[self.auth_df['citizen_id'] == entity_value]
            if not self.complaints_df.empty and 'citizen_id' in self.complaints_df.columns:
                results['complaints'] = self.complaints_df[self.complaints_df['citizen_id'] == entity_value]
        return results

    def get_affected_citizens(self) -> List[str]:
        """Return list of compromised citizen IDs."""
        return list(self.compromised_citizens)

    def get_attacker_ips(self) -> List[str]:
        """Return list of attacker IPs."""
        return list(self.attacker_ips)

    def generate_incident_report(self) -> str:
        """Generate markdown incident report."""
        report = f"# Security Incident Report\n\n"
        report += "## Executive Summary\n"
        report += f"A coordinated attack was detected involving {len(self.attacker_ips)} attacker IPs "
        report += f"resulting in the compromise of {len(self.compromised_citizens)} citizen accounts.\n\n"
        
        report += "## Attack Timeline\n"
        for event in self.timeline[:20]: # Limit for brevity
            report += f"- **{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}** [{event.phase}] ({event.event_id}): {event.description}\n"
        if len(self.timeline) > 20:
            report += f"- ... and {len(self.timeline) - 20} more events.\n"
            
        report += "\n## Affected Entities\n"
        report += f"- **Compromised Citizens:** {', '.join(list(self.compromised_citizens)[:10])}...\n"
        report += f"- **Attacker Infrastructure:** {', '.join(list(self.attacker_ips)[:10])}...\n"
        
        report += "\n## Recommendations\n"
        report += "- **Containment:** Block attacker IPs at WAF, force password resets for compromised accounts.\n"
        report += "- **Eradication:** Terminate active sessions for compromised users, remove malicious API keys.\n"
        report += "- **Recovery:** Restore impacted PII records, notify affected citizens.\n"
        report += "- **Lessons Learned:** Implement rate limiting on auth endpoints, enhance impossible travel detection.\n"
        
        return report

    def generate_soc_playbook(self) -> str:
        """Generate SOC playbook for this scenario."""
        return """# SOC Playbook: E-Government Credential Stuffing & Exfiltration

## 1. Preparation
- Ensure logging is enabled across WAF, API Gateway, and Auth DB.
- Maintain up-to-date threat intel feeds for known botnet IPs.

## 2. Detection & Analysis
- Monitor for high 403/404 rates on config paths.
- Alert on >10 failed logins per IP within 5 minutes.
- Correlate successful logins with impossible travel geo-velocity.

## 3. Containment
- Auto-block IPs exceeding failed login thresholds at the WAF.
- Suspend accounts exhibiting impossible travel until verified.

## 4. Eradication
- Invalidate session tokens for identified compromised accounts.
- Reset credentials and enforce MFA.

## 5. Recovery
- Monitor subsequent login attempts for contained accounts.
- Verify integrity of any PII accessed during the incident.

## 6. Post-Incident
- Review WAF rule effectiveness.
- Update baseline for normal API payload sizes.
"""

    def export_timeline_to_json(self, output_path: str) -> None:
        """Save timeline as JSON."""
        out_data = []
        for t in self.timeline:
            out_data.append({
                'event_id': t.event_id,
                'timestamp': t.timestamp.isoformat(),
                'source': t.source,
                'phase': t.phase,
                'description': t.description,
                'severity': t.severity,
                'related_entities': t.related_entities
            })
        with open(output_path, 'w') as f:
            json.dump(out_data, f, indent=2)

    def plot_attack_timeline(self, save_path: str = None) -> None:
        """Plot attack timeline."""
        if not self.timeline:
            return
            
        phases = [t.phase for t in self.timeline]
        times = [t.timestamp for t in self.timeline]
        
        plt.figure(figsize=(12, 6))
        plt.scatter(times, phases, alpha=0.5, c='red')
        plt.title('Attack Timeline by Phase')
        plt.xlabel('Time')
        plt.ylabel('Attack Phase')
        plt.grid(True)
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()
        plt.close()

if __name__ == '__main__':
    import os
    import dataclasses
    
    PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    RAW_DIR = os.path.join(PROJECT_ROOT, 'data', 'raw')
    PROCESSED_DIR = os.path.join(PROJECT_ROOT, 'data', 'processed')
    
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    
    waf_df = pd.read_csv(os.path.join(RAW_DIR, 'web_waf_logs.csv'))
    api_df = pd.read_csv(os.path.join(RAW_DIR, 'api_gateway_logs.csv'))
    auth_df = pd.read_csv(os.path.join(RAW_DIR, 'auth_db_audit_logs.csv'))
    complaints_df = pd.read_json(os.path.join(RAW_DIR, 'citizen_complaints.json'))
    
    engine = IncidentCorrelationEngine()
    engine.load_all_sources(waf_df, api_df, auth_df, complaints_df)
    
    engine.identify_attack_phases()
    engine.build_timeline()
    affected = engine.get_affected_citizens()
    attackers = engine.get_attacker_ips()
    
    report = engine.generate_incident_report()
    
    with open(os.path.join(PROCESSED_DIR, 'incident_report.md'), 'w') as f:
        f.write(report)
        
    def custom_serializer(obj):
        if isinstance(obj, pd.Timestamp):
            return obj.isoformat()
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return str(obj)

    results = {
        'phases': [dataclasses.asdict(p) for p in engine.attack_phases],
        'timeline_events': [dataclasses.asdict(t) for t in engine.timeline],
        'affected_citizens': affected,
        'attacker_ips': attackers,
        'total_events_correlated': len(engine.timeline)
    }
    
    with open(os.path.join(PROCESSED_DIR, 'incident_timeline.json'), 'w') as f:
        json.dump(results, f, default=custom_serializer, indent=2)
        
    print(f"Correlation Engine Complete. Correlated {results['total_events_correlated']} events.")
