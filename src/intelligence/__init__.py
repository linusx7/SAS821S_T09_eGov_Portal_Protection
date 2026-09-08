"""
Intelligence module for SAS821S e-Government Portal Protection project.
Contains incident correlation, STIX threat intelligence, and NLP ticket mining capabilities.
"""

from .correlation_engine import IncidentCorrelationEngine, AttackPhase, TimelineEvent
from .stix_threat_intel import ThreatIntelligenceManager
from .nlp_ticket_miner import CitizenTicketMiner

__all__ = [
    'IncidentCorrelationEngine',
    'AttackPhase',
    'TimelineEvent',
    'ThreatIntelligenceManager',
    'CitizenTicketMiner'
]
