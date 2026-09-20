"""
Synthetic Data Generation Module for e-Government Portal Protection.
Generates correlated datasets for WAF, API Gateway, Auth DB, and Complaints.
"""

import os
import uuid
import json
import random
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from faker import Faker

# Constants
SEED = 42
NUM_CITIZENS = 500
START_TIME = datetime(2026, 8, 15, 0, 0, 0)
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "raw")

# IP Ranges
NORMAL_IP_PREFIX = "192.0.2."
RECON_IP_PREFIX = "198.51.100."
BOTNET_IP_PREFIX = "203.0.113."

def init_random():
    np.random.seed(SEED)
    random.seed(SEED)
    Faker.seed(SEED)

def get_random_ip(prefix):
    return f"{prefix}{random.randint(1, 254)}"

def get_event_id():
    return f"EVT-{uuid.uuid4().hex[:8].upper()}"

def get_token_id():
    return f"TOK-{uuid.uuid4().hex[:8].upper()}"

def get_ticket_id():
    return f"TKT-{random.randint(100000, 999999)}"

def main():
    init_random()
    fake = Faker()
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Generate common entities
    citizen_ids = [f"CIT-{str(i).zfill(6)}" for i in range(1, NUM_CITIZENS + 1)]
    compromised_citizens = random.sample(citizen_ids, k=50)
    
    # Store global state
    waf_logs = []
    api_logs = []
    auth_logs = []
    complaints = []
    
    # Locations
    namibian_cities = [
        {"city": "Windhoek", "lat": -22.5609, "lon": 17.0658},
        {"city": "Walvis Bay", "lat": -22.9575, "lon": 14.5053},
        {"city": "Swakopmund", "lat": -22.6792, "lon": 14.5272},
        {"city": "Oshakati", "lat": -17.7833, "lon": 15.6833},
        {"city": "Rundu", "lat": -17.9333, "lon": 19.7667}
    ]
    attack_cities = [
        {"city": "Moscow", "country": "Russia", "lat": 55.7558, "lon": 37.6173},
        {"city": "Beijing", "country": "China", "lat": 39.9042, "lon": 116.4074},
        {"city": "São Paulo", "country": "Brazil", "lat": -23.5505, "lon": -46.6333}
    ]
    
    user_agents_normal = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0"
    ]
    user_agents_attack = ["python-requests/2.28.2", "curl/7.88.1", "Go-http-client/1.1"]
    
    # Background Traffic Generation (48 hours)
    for hour in range(48):
        current_hour_start = START_TIME + timedelta(hours=hour)
        
        # Normal WAF / API / Auth
        num_normal = random.randint(100, 150)
        for _ in range(num_normal):
            ts = current_hour_start + timedelta(seconds=random.randint(0, 3599))
            ip = get_random_ip(NORMAL_IP_PREFIX)
            session = str(uuid.uuid4())
            cid = random.choice(citizen_ids)
            city = random.choice(namibian_cities)
            
            # WAF
            waf_logs.append({
                "event_id": get_event_id(), "timestamp": ts.isoformat() + "Z",
                "src_ip": ip, "session_id": session, "http_method": "GET",
                "url_path": random.choice(["/portal", "/api/v1/services", "/api/v1/citizen/profile"]),
                "status_code": random.choice([200, 301, 200, 200]),
                "user_agent": random.choice(user_agents_normal), "bytes_sent": random.randint(500, 2000),
                "waf_action": "ALLOW", "attack_type": "BENIGN", "country": "Namibia"
            })
            
            # API
            if random.random() < 0.6:
                api_logs.append({
                    "event_id": get_event_id(), "timestamp": ts.isoformat() + "Z",
                    "session_id": session, "src_ip": ip,
                    "endpoint": random.choice(["/api/v1/services", "/api/v1/citizen/profile"]),
                    "token_id": get_token_id(), "citizen_id": cid,
                    "request_payload_bytes": random.randint(100, 500),
                    "response_time_ms": random.randint(50, 300),
                    "http_status": 200, "is_anomalous_scraping": 0
                })
                
            # Auth
            if random.random() < 0.2:
                auth_logs.append({
                    "event_id": get_event_id(), "timestamp": ts.isoformat() + "Z",
                    "citizen_id": cid, "auth_event": "LOGIN_SUCCESS" if random.random() > 0.1 else "LOGIN_FAILED",
                    "src_ip": ip, "geo_country": "Namibia", "geo_city": city["city"],
                    "latitude": city["lat"], "longitude": city["lon"],
                    "db_query": f"SELECT * FROM users WHERE id='{cid}'",
                    "rows_returned": 1, "db_execution_ms": random.randint(5, 20),
                    "is_impossible_travel": 0
                })

    # Phase 1: Recon (Hour 0-2)
    for hour in range(0, 2):
        for _ in range(300):
            ts = START_TIME + timedelta(hours=hour, seconds=random.randint(0, 3599))
            ip = get_random_ip(RECON_IP_PREFIX)
            session = str(uuid.uuid4())
            waf_logs.append({
                "event_id": get_event_id(), "timestamp": ts.isoformat() + "Z",
                "src_ip": ip, "session_id": session, "http_method": random.choice(["GET", "POST"]),
                "url_path": random.choice(["/admin", "/api/v1/tax/records", "/.env", "/backup"]),
                "status_code": random.choice([403, 404]),
                "user_agent": random.choice(user_agents_attack), "bytes_sent": random.randint(100, 300),
                "waf_action": "BLOCK", "attack_type": "API_RECON", "country": "Unknown"
            })

    # Phase 2: Credential Stuffing (Hour 2-6)
    for hour in range(2, 6):
        for _ in range(400):
            ts = START_TIME + timedelta(hours=hour, seconds=random.randint(0, 3599))
            ip = get_random_ip(BOTNET_IP_PREFIX)
            session = str(uuid.uuid4())
            cid = random.choice(citizen_ids)
            
            waf_logs.append({
                "event_id": get_event_id(), "timestamp": ts.isoformat() + "Z",
                "src_ip": ip, "session_id": session, "http_method": "POST",
                "url_path": "/api/v1/citizen/login", "status_code": 401,
                "user_agent": random.choice(user_agents_attack), "bytes_sent": random.randint(100, 200),
                "waf_action": "CHALLENGE", "attack_type": "CREDENTIAL_STUFFING", "country": "Unknown"
            })
            
            auth_logs.append({
                "event_id": get_event_id(), "timestamp": ts.isoformat() + "Z",
                "citizen_id": cid, "auth_event": "LOGIN_FAILED",
                "src_ip": ip, "geo_country": "Unknown", "geo_city": "Unknown",
                "latitude": 0.0, "longitude": 0.0,
                "db_query": f"SELECT * FROM users WHERE id='{cid}'",
                "rows_returned": 0, "db_execution_ms": random.randint(5, 10),
                "is_impossible_travel": 0
            })

    # Phase 3: Account Takeover (Hour 6-8)
    for hour in range(6, 8):
        for cid in compromised_citizens:
            ts = START_TIME + timedelta(hours=hour, seconds=random.randint(0, 3599))
            ip = get_random_ip(BOTNET_IP_PREFIX)
            atk_loc = random.choice(attack_cities)
            
            # Legitimate login first (to trigger impossible travel)
            legit_ts = ts - timedelta(minutes=random.randint(10, 30))
            legit_ip = get_random_ip(NORMAL_IP_PREFIX)
            legit_loc = random.choice(namibian_cities)
            
            auth_logs.append({
                "event_id": get_event_id(), "timestamp": legit_ts.isoformat() + "Z",
                "citizen_id": cid, "auth_event": "LOGIN_SUCCESS",
                "src_ip": legit_ip, "geo_country": "Namibia", "geo_city": legit_loc["city"],
                "latitude": legit_loc["lat"], "longitude": legit_loc["lon"],
                "db_query": f"SELECT * FROM users WHERE id='{cid}'",
                "rows_returned": 1, "db_execution_ms": random.randint(5, 20),
                "is_impossible_travel": 0
            })
            
            auth_logs.append({
                "event_id": get_event_id(), "timestamp": ts.isoformat() + "Z",
                "citizen_id": cid, "auth_event": "LOGIN_SUCCESS",
                "src_ip": ip, "geo_country": atk_loc["country"], "geo_city": atk_loc["city"],
                "latitude": atk_loc["lat"], "longitude": atk_loc["lon"],
                "db_query": f"SELECT * FROM users WHERE id='{cid}'",
                "rows_returned": 1, "db_execution_ms": random.randint(5, 20),
                "is_impossible_travel": 1
            })

    # Phase 4 & 5: API Scraping & DB Exfiltration (Hour 8-14)
    # Phase 4: 8-12, Phase 5: 12-14
    for hour in range(8, 14):
        for cid in compromised_citizens:
            ts = START_TIME + timedelta(hours=hour, seconds=random.randint(0, 3599))
            ip = get_random_ip(BOTNET_IP_PREFIX)
            session = str(uuid.uuid4())
            token = get_token_id()
            
            if hour < 12: # API Scraping
                for _ in range(random.randint(10, 20)):
                    ts += timedelta(seconds=random.randint(1, 5))
                    api_logs.append({
                        "event_id": get_event_id(), "timestamp": ts.isoformat() + "Z",
                        "session_id": session, "src_ip": ip,
                        "endpoint": random.choice(["/api/v1/tax/records", "/api/v1/civil/registry"]),
                        "token_id": token, "citizen_id": cid,
                        "request_payload_bytes": random.randint(100, 500),
                        "response_time_ms": random.randint(500, 2000),
                        "http_status": 200, "is_anomalous_scraping": 1
                    })
            else: # DB Exfiltration
                ts += timedelta(seconds=random.randint(10, 50))
                auth_logs.append({
                    "event_id": get_event_id(), "timestamp": ts.isoformat() + "Z",
                    "citizen_id": cid, "auth_event": "PRIVILEGE_ESCALATION",
                    "src_ip": ip, "geo_country": "Unknown", "geo_city": "Unknown",
                    "latitude": 0.0, "longitude": 0.0,
                    "db_query": f"SELECT * FROM citizen_registry WHERE criteria LIKE '%{fake.word()}%'",
                    "rows_returned": random.randint(5000, 15000), "db_execution_ms": random.randint(1500, 5000),
                    "is_impossible_travel": 0
                })

    # Phase 6: Complaints (Hour 14+)
    for hour in range(14, 48):
        # 1-3 complaints per hour normally
        num_complaints = random.randint(3, 10)
        for _ in range(num_complaints):
            ts = START_TIME + timedelta(hours=hour, seconds=random.randint(0, 3599))
            is_attack_related = random.random() < 0.7
            
            if is_attack_related:
                cid = random.choice(compromised_citizens)
                atk_ip = get_random_ip(BOTNET_IP_PREFIX)
                texts = [
                    f"I cannot access my tax portal account. It says my account has been locked after multiple failed login attempts. I did not try to log in today. The suspicious IP was {atk_ip}",
                    f"Someone accessed my civil registration profile from an IP address in Russia. I have never traveled outside Namibia.",
                    f"The e-Government portal has been extremely slow since this morning. I cannot submit my tax returns before the deadline.",
                    f"I received an email saying my password was changed but I did not request this. Please investigate immediately."
                ]
                text = random.choice(texts)
                category = random.choice(["ACCOUNT_LOCKOUT", "UNAUTHORIZED_ACCESS", "IDENTITY_THEFT", "DATA_BREACH"])
                urgency = "HIGH"
            else:
                cid = random.choice(citizen_ids)
                text = fake.paragraph(nb_sentences=3)
                category = "PORTAL_SLOWDOWN"
                urgency = random.choice(["LOW", "MEDIUM"])
                
            complaints.append({
                "ticket_id": get_ticket_id(), "timestamp": ts.isoformat() + "Z",
                "citizen_id": cid, "reported_ip": atk_ip if is_attack_related else "",
                "complaint_text": text, "urgency_level": urgency, "category": category
            })

    # Sort logs by timestamp
    waf_df = pd.DataFrame(waf_logs).sort_values(by="timestamp")
    api_df = pd.DataFrame(api_logs).sort_values(by="timestamp")
    auth_df = pd.DataFrame(auth_logs).sort_values(by="timestamp")
    complaints_df = pd.DataFrame(complaints).sort_values(by="timestamp")

    # Save to CSV / JSON
    waf_df.to_csv(os.path.join(OUTPUT_DIR, "web_waf_logs.csv"), index=False)
    api_df.to_csv(os.path.join(OUTPUT_DIR, "api_gateway_logs.csv"), index=False)
    auth_df.to_csv(os.path.join(OUTPUT_DIR, "auth_db_audit_logs.csv"), index=False)
    
    with open(os.path.join(OUTPUT_DIR, "citizen_complaints.json"), "w") as f:
        json.dump(complaints, f, indent=4)
        
    print(f"Generated web_waf_logs.csv: {len(waf_df)} records")
    print(f"Generated api_gateway_logs.csv: {len(api_df)} records")
    print(f"Generated auth_db_audit_logs.csv: {len(auth_df)} records")
    print(f"Generated citizen_complaints.json: {len(complaints)} records")
    print(f"Data saved to: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
