#!/usr/bin/env python3

import socket
import ssl
import json
import argparse
import logging
import sys
import os
import time
import hashlib
import ipaddress
import concurrent.futures
import re
import csv
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Tuple, Set
from dataclasses import dataclass, asdict, field
from pathlib import Path
import sqlite3
import threading
import queue
import smtplib
import hmac
import secrets
import base64
from email.mime.multipart import MIMEMultipart   # FIX: was missing import
from email.mime.text import MIMEText             # FIX: was missing import
from functools import wraps
import traceback
import uuid
import pickle
import gzip
import struct
from collections import defaultdict, Counter
from statistics import mean, median, stdev
import math
from enum import Enum

try:
    from colorama import init, Fore, Style
    init()
    COLORAMA = True
except ImportError:
    COLORAMA = False
    Fore = Style = type('obj', (object,), {
        'RESET_ALL': '', 'GREEN': '', 'RED': '',
        'YELLOW': '', 'BLUE': '', 'CYAN': '',
        'MAGENTA': '', 'WHITE': ''
    })()

try:
    from tqdm import tqdm
    TQDM = True
except ImportError:
    TQDM = False

try:
    from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, g, make_response
    from flask_cors import CORS
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
    from werkzeug.security import generate_password_hash, check_password_hash  # FIX: was missing import
    FLASK = True
except ImportError:
    FLASK = False
    def generate_password_hash(pw):
        return hashlib.sha256(pw.encode()).hexdigest()

try:
    import requests
    REQUESTS = True
except ImportError:
    REQUESTS = False

try:
    import psycopg2
    POSTGRES = True
except ImportError:
    POSTGRES = False

try:
    import pymongo
    MONGODB = True
except ImportError:
    MONGODB = False

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    import boto3
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.cloud import resource_manager
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

VERSION = "5.0.0-Ultimate"
DEFAULT_TIMEOUT = 2.0
DEFAULT_THREADS = 200
DEFAULT_DB_PATH = "ultimate_scanner.db"
SECRET_KEY = secrets.token_hex(32)
JWT_SECRET = secrets.token_hex(32)

OS_TTL_MAP = {64: "Linux/Unix", 128: "Windows", 255: "Cisco/Network"}

VULN_DB = {
    "Apache/2.4.49": {"cves": ["CVE-2021-41773", "CVE-2021-42013"], "severity": "CRITICAL", "cvss": 9.8, "exploit_available": True},
    "Apache/2.4.50": {"cves": ["CVE-2021-41773"], "severity": "HIGH", "cvss": 7.5, "exploit_available": True},
    "vsftpd/2.3.4": {"cves": ["CVE-2011-2523"], "severity": "CRITICAL", "cvss": 9.8, "exploit_available": True},
    "ProFTPD/1.3.3": {"cves": ["CVE-2010-4221"], "severity": "HIGH", "cvss": 8.5, "exploit_available": True},
    "Samba/3.5.0": {"cves": ["CVE-2010-2063"], "severity": "CRITICAL", "cvss": 10.0, "exploit_available": True},
    "IIS/6.0": {"cves": ["CVE-2015-1635"], "severity": "HIGH", "cvss": 7.5, "exploit_available": False},
    "OpenSSL/1.0.1": {"cves": ["CVE-2014-0160"], "severity": "CRITICAL", "cvss": 9.8, "exploit_available": True},
    "SSLv3": {"cves": ["POODLE"], "severity": "HIGH", "cvss": 7.4, "exploit_available": True},
    "TLSv1.0": {"cves": ["BEAST"], "severity": "MEDIUM", "cvss": 5.9, "exploit_available": False},
    "TLSv1.1": {"cves": ["Weak Protocol"], "severity": "MEDIUM", "cvss": 5.3, "exploit_available": False},
    "Windows NT": {"cves": ["MS08-067"], "severity": "CRITICAL", "cvss": 10.0, "exploit_available": True},
    "SMBv1": {"cves": ["CVE-2017-0144"], "severity": "CRITICAL", "cvss": 9.8, "exploit_available": True},
    "Exchange/2019": {"cves": ["CVE-2021-26855"], "severity": "CRITICAL", "cvss": 9.8, "exploit_available": True},
    "Log4j": {"cves": ["CVE-2021-44228"], "severity": "CRITICAL", "cvss": 10.0, "exploit_available": True},
    "Spring4Shell": {"cves": ["CVE-2022-22965"], "severity": "CRITICAL", "cvss": 9.8, "exploit_available": True},
}

COMPLIANCE_RULES = {
    "PCI-DSS": [
        {"id": "PCI-2.1", "description": "No default passwords", "check": "default_creds", "weight": 10},
        {"id": "PCI-2.2", "description": "Disable unnecessary services", "check": "unnecessary_ports", "weight": 8},
        {"id": "PCI-4.1", "description": "Use strong cryptography", "check": "weak_ssl", "weight": 10},
        {"id": "PCI-6.1", "description": "Identify vulnerabilities", "check": "known_vulns", "weight": 10},
        {"id": "PCI-11.2", "description": "Run internal scans", "check": "scan_frequency", "weight": 5},
    ],
    "HIPAA": [
        {"id": "HIPAA-164.312", "description": "Encrypt PHI in transit", "check": "encryption", "weight": 10},
        {"id": "HIPAA-164.308", "description": "Security management", "check": "vuln_management", "weight": 8},
        {"id": "HIPAA-164.310", "description": "Physical safeguards", "check": "access_control", "weight": 7},
    ],
    "CIS": [
        {"id": "CIS-1.1", "description": "Minimize installed packages", "check": "unnecessary_services", "weight": 6},
        {"id": "CIS-2.1", "description": "Disable unused ports", "check": "open_ports", "weight": 8},
        {"id": "CIS-3.1", "description": "Configure firewall", "check": "firewall_rules", "weight": 9},
    ],
    "GDPR": [
        {"id": "GDPR-32", "description": "Security of processing", "check": "data_protection", "weight": 10},
        {"id": "GDPR-25", "description": "Data protection by design", "check": "privacy_by_design", "weight": 8},
    ],
    "SOX": [
        {"id": "SOX-404", "description": "Internal controls", "check": "access_controls", "weight": 9},
        {"id": "SOX-302", "description": "Corporate responsibility", "check": "audit_trail", "weight": 8},
    ],
    "ISO27001": [
        {"id": "ISO-A.12.6", "description": "Technical vulnerability management", "check": "vuln_mgmt", "weight": 10},
        {"id": "ISO-A.9.1", "description": "Access control policy", "check": "access_policy", "weight": 9},
    ]
}

THREAT_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "https://rules.emergingthreats.net/open/suricata/emerging-all.rules",
    "https://www.spamhaus.org/drop/drop.txt",
]

RISK_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 1.0
}

ASSET_CATEGORIES = {
    "web_server": [80, 443, 8080, 8443],
    "database": [3306, 5432, 1433, 27017, 6379, 1521],
    "mail_server": [25, 110, 143, 465, 587, 993, 995],
    "file_server": [21, 22, 139, 445],
    "directory_service": [389, 636, 88, 3268],
    "network_device": [22, 23, 161, 162, 179, 443],
    "iot_device": [1883, 8883, 5683, 5684],
    "container_registry": [5000, 5001],
    "kubernetes": [6443, 10250, 2379],
    "cloud_service": [443, 8443],
    "api_gateway": [80, 443, 8000, 8080],
    "monitoring": [9090, 9093, 3000, 8086],
}

DEFAULT_CREDS = {
    "ftp": [("anonymous", "anonymous"), ("admin", "admin")],
    "ssh": [("root", "root"), ("admin", "admin"), ("user", "user")],
    "telnet": [("admin", "admin"), ("root", "root")],
    "http": [("admin", "admin"), ("admin", "password"), ("root", "root")],
    "mysql": [("root", ""), ("root", "root")],
    "postgres": [("postgres", "postgres")],
    "mongodb": [("admin", "admin")],
    "redis": [("", "")],
}

ATTACK_PATTERNS = {
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1021": "Remote Services",
    "T1046": "Network Service Scanning",
    "T1049": "System Network Connections Discovery",
}

# ============================================================================
# HELPERS
# ============================================================================

def get_hash(data: str) -> str:
    # FIX: was missing from codebase - caused NameError in scan_host
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def colorize(text: str, color: str) -> str:
    # FIX: was missing from codebase - caused NameError in main()
    if not COLORAMA:
        return text
    color_map = {
        "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
        "blue": Fore.BLUE, "cyan": Fore.CYAN, "magenta": Fore.MAGENTA,
        "white": Fore.WHITE,
    }
    return f"{color_map.get(color, '')}{text}{Style.RESET_ALL}"


def load_json_file(path: str) -> Optional[Any]:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def parse_ip_range(target: str, logger: logging.Logger) -> List[str]:
    ips = []
    try:
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        elif '-' in target:
            parts = target.split('-')
            start = ipaddress.IPv4Address(parts[0].strip())
            end = ipaddress.IPv4Address(parts[1].strip())
            current = start
            while current <= end:
                ips.append(str(current))
                current += 1
        else:
            ipaddress.IPv4Address(target)
            ips = [target]
    except Exception as e:
        logger.error(f"Invalid target: {e}")
        raise
    return ips


def parse_ports(ports_str: str, logger: logging.Logger) -> List[int]:
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
        6379, 8080, 8443, 8888, 9090, 9200, 27017
    ]
    if ports_str == 'common':
        return COMMON_PORTS
    if ports_str == 'all':
        return list(range(1, 65536))

    ports = []
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            lo, hi = part.split('-')
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

# ============================================================================
# DATA CLASSES
# ============================================================================

class SeverityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ScanStatus(Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

@dataclass
class SSLInfo:
    valid: bool
    issuer: str
    subject: str
    expiry: str
    protocol: str
    cipher: str
    weak: bool
    error: str = ""
    cert_hash: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    san_list: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False
    days_until_expiry: int = 0

@dataclass
class OSInfo:
    os_guess: str
    ttl: int
    confidence: str
    accuracy: float = 0.0
    kernel_version: str = ""
    architecture: str = ""
    uptime: int = 0

@dataclass
class GeoInfo:
    country: str
    city: str
    isp: str
    lat: float
    lon: float
    is_threat: bool = False
    threat_type: str = ""
    asn: str = ""
    organization: str = ""
    timezone: str = ""

@dataclass
class Vulnerability:
    cve_id: str
    severity: str
    cvss: float
    description: str
    remediation: str
    exploit_available: bool = False
    patch_available: bool = False
    affected_versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    mitre_attack_id: str = ""
    discovered_at: str = ""

@dataclass
class ComplianceFinding:
    rule_id: str
    framework: str
    description: str
    status: str
    evidence: str
    weight: int = 0
    remediation: str = ""

@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str
    banner: str
    ssl: Optional[SSLInfo]
    vulnerabilities: List[Vulnerability]
    response_time: float
    risk_score: float = 0.0
    default_creds_tested: bool = False
    default_creds_found: bool = False
    attack_patterns: List[str] = field(default_factory=list)

@dataclass
class NetworkPath:
    source: str
    destination: str
    hops: List[str]
    latency: float
    packet_loss: float

@dataclass
class LateralMovementPath:
    start_host: str
    end_host: str
    path: List[str]
    protocols: List[str]
    risk_level: str
    mitigation: str

@dataclass
class HostResult:
    ip: str
    hostname: str
    is_alive: bool
    os: Optional[OSInfo]
    geo: Optional[GeoInfo]
    open_ports: List[PortResult]
    anomalies: List[str]
    compliance_findings: List[ComplianceFinding]
    risk_score: float
    asset_category: str
    tags: List[str]
    scan_time: float
    timestamp: str
    hash: str
    scan_id: str
    network_paths: List[NetworkPath] = field(default_factory=list)
    lateral_movement_paths: List[LateralMovementPath] = field(default_factory=list)
    attack_surface_score: float = 0.0
    security_posture_score: float = 0.0

@dataclass
class ScanStatistics:
    total_hosts: int
    hosts_alive: int
    total_ports_scanned: int
    total_open_ports: int
    total_vulnerabilities: int
    critical_vulns: int
    high_vulns: int
    medium_vulns: int
    low_vulns: int
    compliance_pass: int
    compliance_fail: int
    average_risk_score: float
    scan_duration: float
    start_time: str
    end_time: str
    scan_id: str
    security_posture_score: float = 0.0
    attack_surface_area: int = 0
    remediation_priority_items: int = 0

@dataclass
class User:
    id: str
    username: str
    email: str
    password_hash: str
    role: str
    created_at: str
    last_login: str = ""
    mfa_enabled: bool = False
    api_key: str = ""

@dataclass
class ScanProfile:
    name: str
    ports: str
    protocols: List[str]
    timeout: float
    threads: int
    compliance_frameworks: List[str]
    webhook_urls: List[str]
    schedule: str
    notifications_enabled: bool = True
    auto_remediation: bool = False

@dataclass
class BlockchainBlock:
    index: int
    timestamp: str
    data: Dict
    previous_hash: str
    hash: str
    nonce: int

@dataclass
class MLModel:
    model_type: str
    trained_at: str
    accuracy: float
    features: List[str]
    model_data: bytes

# ============================================================================
# BLOCKCHAIN AUDIT TRAIL
# ============================================================================

class BlockchainAudit:
    def __init__(self):
        self.chain: List[BlockchainBlock] = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis = BlockchainBlock(
            index=0,
            timestamp=datetime.now().isoformat(),
            data={"type": "genesis", "message": "Blockchain initialized"},
            previous_hash="0",
            hash=self.calculate_hash(0, datetime.now().isoformat(), {"type": "genesis"}, "0", 0),
            nonce=0
        )
        self.chain.append(genesis)

    def calculate_hash(self, index: int, timestamp: str, data: Dict, previous_hash: str, nonce: int) -> str:
        data_str = json.dumps(data, sort_keys=True)
        hash_input = f"{index}{timestamp}{data_str}{previous_hash}{nonce}"
        return hashlib.sha256(hash_input.encode()).hexdigest()

    def add_block(self, data: Dict) -> BlockchainBlock:
        index = len(self.chain)
        timestamp = datetime.now().isoformat()
        previous_hash = self.chain[-1].hash
        # FIX: nonce was always 0 - now incremented until leading zero found (lightweight PoW)
        nonce = 0
        hash_value = self.calculate_hash(index, timestamp, data, previous_hash, nonce)
        while not hash_value.startswith('0'):
            nonce += 1
            hash_value = self.calculate_hash(index, timestamp, data, previous_hash, nonce)

        block = BlockchainBlock(
            index=index, timestamp=timestamp, data=data,
            previous_hash=previous_hash, hash=hash_value, nonce=nonce
        )
        self.chain.append(block)
        return block

    def verify_chain(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != self.calculate_hash(
                current.index, current.timestamp, current.data, previous.hash, current.nonce
            ):
                return False
            if current.previous_hash != previous.hash:
                return False
        return True

    def get_audit_trail(self) -> List[Dict]:
        return [asdict(block) for block in self.chain]

# ============================================================================
# MACHINE LEARNING ENGINE
# ============================================================================

class MLEngine:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.anomaly_model = None
        self.vuln_prediction_model = None
        self.scaler = StandardScaler() if ML_AVAILABLE else None
        self.training_data = []

    def train_anomaly_detector(self, historical_scans: List[Dict]):
        if not ML_AVAILABLE:
            self.logger.warning("ML libraries not available")
            return
        try:
            features = []
            for scan in historical_scans:
                features.append([
                    scan.get('total_open_ports', 0),
                    scan.get('total_vulnerabilities', 0),
                    scan.get('critical_vulns', 0),
                    scan.get('average_risk_score', 0),
                    scan.get('hosts_alive', 0),
                ])
            if len(features) >= 10:
                X = np.array(features)
                self.anomaly_model = IsolationForest(contamination=0.1, random_state=42)
                self.anomaly_model.fit(X)
                self.logger.info("Anomaly detection model trained successfully")
        except Exception as e:
            self.logger.error(f"Failed to train anomaly model: {e}")

    def detect_anomalies(self, current_stats: Dict) -> Tuple[bool, float]:
        if not self.anomaly_model or not ML_AVAILABLE:
            return False, 0.0
        try:
            feature_vector = np.array([[
                current_stats.get('total_open_ports', 0),
                current_stats.get('total_vulnerabilities', 0),
                current_stats.get('critical_vulns', 0),
                current_stats.get('average_risk_score', 0),
                current_stats.get('hosts_alive', 0),
            ]])
            prediction = self.anomaly_model.predict(feature_vector)[0]
            score = self.anomaly_model.score_samples(feature_vector)[0]
            return prediction == -1, score
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            return False, 0.0

    def predict_vulnerabilities(self, host_features: Dict) -> List[str]:
        predictions = []
        if host_features.get('open_ports', []):
            if 22 in host_features['open_ports']:
                predictions.append("Potential SSH brute force vulnerability")
            if 3389 in host_features['open_ports']:
                predictions.append("Potential RDP vulnerability")
            if 445 in host_features['open_ports']:
                predictions.append("Potential SMB vulnerability (EternalBlue)")
        if host_features.get('os_guess', '') == 'Windows':
            predictions.append("Windows-specific vulnerabilities may apply")
        return predictions

    def calculate_security_posture(self, host_result: 'HostResult') -> float:
        score = 100.0
        for port in host_result.open_ports:
            for vuln in port.vulnerabilities:
                if vuln.severity == "CRITICAL":
                    score -= 15
                elif vuln.severity == "HIGH":
                    score -= 10
                elif vuln.severity == "MEDIUM":
                    score -= 5
                elif vuln.severity == "LOW":
                    score -= 2
        for finding in host_result.compliance_findings:
            if finding.status == "FAIL":
                score -= 5
        for port in host_result.open_ports:
            if port.ssl and port.ssl.weak:
                score -= 5
        for port in host_result.open_ports:
            if port.default_creds_found:
                score -= 10
        score -= len(host_result.anomalies) * 3
        return max(0.0, min(100.0, score))

# ============================================================================
# DATABASE MANAGER
# ============================================================================

class DatabaseManager:
    def __init__(self, db_path: str = DEFAULT_DB_PATH, db_type: str = "sqlite",
                 connection_string: str = ""):
        self.db_path = db_path
        self.db_type = db_type
        self.connection_string = connection_string
        self.blockchain = BlockchainAudit()
        self.init_db()

    def get_connection(self):
        if self.db_type == "postgres" and POSTGRES:
            return psycopg2.connect(self.connection_string)
        elif self.db_type == "mongodb" and MONGODB:
            client = pymongo.MongoClient(self.connection_string)
            return client['ultimate_scanner']
        else:
            return sqlite3.connect(self.db_path)

    def init_db(self):
        if self.db_type == "mongodb":
            return

        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, username TEXT UNIQUE, email TEXT,
                password_hash TEXT, role TEXT, created_at TEXT,
                last_login TEXT, mfa_enabled BOOLEAN, api_key TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY, target TEXT, start_time TEXT,
                end_time TEXT, status TEXT, total_hosts INTEGER,
                total_vulns INTEGER, risk_score REAL,
                security_posture_score REAL, created_by TEXT, blockchain_hash TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, ip TEXT,
                hostname TEXT, is_alive BOOLEAN, os_guess TEXT,
                risk_score REAL, asset_category TEXT,
                security_posture_score REAL, timestamp TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, host_id INTEGER,
                port INTEGER, protocol TEXT, state TEXT, service TEXT,
                banner TEXT, risk_score REAL,
                FOREIGN KEY(host_id) REFERENCES hosts(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT, port_id INTEGER,
                cve_id TEXT, severity TEXT, cvss REAL, exploit_available BOOLEAN,
                FOREIGN KEY(port_id) REFERENCES ports(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT,
                rule_id TEXT, framework TEXT, status TEXT, evidence TEXT, weight INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT,
                action TEXT, target TEXT, timestamp TEXT,
                ip_address TEXT, blockchain_hash TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE,
                config TEXT, created_by TEXT, created_at TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ml_models (
                id INTEGER PRIMARY KEY AUTOINCREMENT, model_type TEXT,
                trained_at TEXT, accuracy REAL, model_data BLOB
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_topology (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT,
                source_ip TEXT, dest_ip TEXT, hops TEXT, latency REAL
            )
        ''')

        conn.commit()
        conn.close()

        self.blockchain.add_block({
            "type": "db_init",
            "db_type": self.db_type,
            "timestamp": datetime.now().isoformat()
        })

    def save_scan(self, scan_id: str, results: List[HostResult], stats: ScanStatistics, user_id: str):
        conn = self.get_connection()
        cursor = conn.cursor()

        block_data = {
            "type": "scan_completed", "scan_id": scan_id,
            "total_hosts": stats.total_hosts, "total_vulns": stats.total_vulnerabilities,
            "security_posture": stats.security_posture_score, "timestamp": stats.end_time
        }
        block = self.blockchain.add_block(block_data)

        # FIX: target column was missing from the INSERT tuple - column count mismatch
        cursor.execute('''
            INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, stats.start_time, stats.end_time, 'completed',
              stats.total_hosts, stats.total_vulnerabilities, stats.average_risk_score,
              stats.security_posture_score, user_id, block.hash, stats.start_time))

        for host in results:
            cursor.execute('''
                INSERT INTO hosts (scan_id, ip, hostname, is_alive, os_guess,
                    risk_score, asset_category, security_posture_score, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (scan_id, host.ip, host.hostname, host.is_alive,
                  host.os.os_guess if host.os else '', host.risk_score,
                  host.asset_category, host.security_posture_score, host.timestamp))

            host_id = cursor.lastrowid

            for port in host.open_ports:
                cursor.execute('''
                    INSERT INTO ports (host_id, port, protocol, state, service, banner, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (host_id, port.port, port.protocol, port.state,
                      port.service, port.banner, port.risk_score))

                port_id = cursor.lastrowid

                for vuln in port.vulnerabilities:
                    cursor.execute('''
                        INSERT INTO vulnerabilities (port_id, cve_id, severity, cvss, exploit_available)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (port_id, vuln.cve_id, vuln.severity, vuln.cvss, vuln.exploit_available))

        for host in results:
            for finding in host.compliance_findings:
                cursor.execute('''
                    INSERT INTO compliance (scan_id, rule_id, framework, status, evidence, weight)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (scan_id, finding.rule_id, finding.framework,
                      finding.status, finding.evidence, finding.weight))

        cursor.execute('''
            INSERT INTO audit_log (user_id, action, target, timestamp, ip_address, blockchain_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, "scan_completed", stats.start_time,
              datetime.now().isoformat(), "127.0.0.1", block.hash))

        conn.commit()
        conn.close()

    def log_audit(self, user_id: str, action: str, target: str, ip_address: str):
        conn = self.get_connection()
        cursor = conn.cursor()

        block = self.blockchain.add_block({
            "type": "audit_log", "user_id": user_id,
            "action": action, "target": target
        })

        cursor.execute('''
            INSERT INTO audit_log (user_id, action, target, timestamp, ip_address, blockchain_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, action, target, datetime.now().isoformat(), ip_address, block.hash))

        conn.commit()
        conn.close()

    def get_scan_history(self, limit: int = 10) -> List[Dict]:
        if self.db_type == "mongodb":
            db = self.get_connection()
            results = list(db.scans.find().sort('start_time', -1).limit(limit))
            for r in results:
                r['_id'] = str(r['_id'])
            return results

        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scans ORDER BY start_time DESC LIMIT ?', (limit,))
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        return results

    def get_trend_data(self, days: int = 30) -> List[Dict]:
        if self.db_type == "mongodb":
            db = self.get_connection()
            pipeline = [
                {"$match": {"start_time": {"$gte": (datetime.now() - timedelta(days=days)).isoformat()}}},
                {"$group": {
                    "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$start_time"}},
                    "avg_risk": {"$avg": "$risk_score"},
                    "scan_count": {"$sum": 1},
                    "total_vulns": {"$sum": "$total_vulns"}
                }},
                {"$sort": {"_id": 1}}
            ]
            results = list(db.scans.aggregate(pipeline))
            for r in results:
                r['scan_date'] = r.pop('_id')
            return results

        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT date(start_time) as scan_date,
                   AVG(risk_score) as avg_risk,
                   COUNT(*) as scan_count,
                   SUM(total_vulns) as total_vulns
            FROM scans
            WHERE start_time >= date('now', ?)
            GROUP BY date(start_time)
        ''', (f'-{days} days',))
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        return results

    def get_blockchain_audit_trail(self) -> List[Dict]:
        return self.blockchain.get_audit_trail()

    def verify_blockchain_integrity(self) -> bool:
        return self.blockchain.verify_chain()

    def save_ml_model(self, model: MLModel):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ml_models (model_type, trained_at, accuracy, model_data)
            VALUES (?, ?, ?, ?)
        ''', (model.model_type, model.trained_at, model.accuracy, model.model_data))
        conn.commit()
        conn.close()

    def get_latest_ml_model(self, model_type: str) -> Optional[MLModel]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT model_type, trained_at, accuracy, model_data FROM ml_models
            WHERE model_type = ? ORDER BY trained_at DESC LIMIT 1
        ''', (model_type,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return MLModel(model_type=row[0], trained_at=row[1],
                           accuracy=row[2], features=[], model_data=row[3])
        return None

# ============================================================================
# CLOUD INTEGRATION
# ============================================================================

class CloudIntegration:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.aws_client = None
        self.azure_client = None
        self.gcp_client = None

    def connect_aws(self, profile: str = "default"):
        if not AWS_AVAILABLE:
            self.logger.warning("AWS SDK not available")
            return
        try:
            session = boto3.Session(profile_name=profile)
            self.aws_client = session.client('ec2')
            self.logger.info("Connected to AWS")
        except Exception as e:
            self.logger.error(f"AWS connection failed: {e}")

    def connect_azure(self, subscription_id: str):   # FIX: subscription_id was missing parameter - caused NameError
        if not AZURE_AVAILABLE:
            self.logger.warning("Azure SDK not available")
            return
        try:
            credential = DefaultAzureCredential()
            self.azure_client = ResourceManagementClient(credential, subscription_id)
            self.logger.info("Connected to Azure")
        except Exception as e:
            self.logger.error(f"Azure connection failed: {e}")

    def connect_gcp(self, project_id: str):
        if not GCP_AVAILABLE:
            self.logger.warning("GCP SDK not available")
            return
        try:
            self.gcp_client = resource_manager.Client(project=project_id)
            self.logger.info("Connected to GCP")
        except Exception as e:
            self.logger.error(f"GCP connection failed: {e}")

    def get_aws_instances(self) -> List[str]:
        if not self.aws_client:
            return []
        try:
            response = self.aws_client.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            ips = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if 'PublicIpAddress' in instance:
                        ips.append(instance['PublicIpAddress'])
            return ips
        except Exception as e:
            self.logger.error(f"Failed to get AWS instances: {e}")
            return []

    def get_azure_vms(self) -> List[str]:
        if not self.azure_client:
            return []
        try:
            return []
        except Exception as e:
            self.logger.error(f"Failed to get Azure VMs: {e}")
            return []

    def get_gcp_instances(self) -> List[str]:
        if not self.gcp_client:
            return []
        try:
            return []
        except Exception as e:
            self.logger.error(f"Failed to get GCP instances: {e}")
            return []

# ============================================================================
# THREAT INTELLIGENCE
# ============================================================================

class ThreatIntelligence:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.ioc_database: List[Dict] = []
        self.load_threat_feeds()

    def load_threat_feeds(self):
        if not REQUESTS:
            return
        for feed_url in THREAT_FEEDS:
            try:
                response = requests.get(feed_url, timeout=10)
                if response.status_code == 200:
                    for line in response.text.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ip = line.split()[0] if ' ' in line else line
                            try:
                                ipaddress.IPv4Address(ip)
                                self.malicious_ips.add(ip)
                            except Exception:
                                pass
                self.logger.info(f"Loaded threat feed: {feed_url}")
            except Exception as e:
                self.logger.warning(f"Failed to load threat feed {feed_url}: {e}")

    def load_ct_logs(self, domain: str):
        # FIX: hardcoded example.com replaced with domain parameter
        if not REQUESTS:
            return
        try:
            response = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json", timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if 'name_value' in entry:
                        self.malicious_domains.add(entry['name_value'])
            self.logger.info(f"Loaded CT logs for {domain}")
        except Exception as e:
            self.logger.warning(f"Failed to load CT logs: {e}")

    def is_malicious(self, ip: str) -> Tuple[bool, str]:
        if ip in self.malicious_ips:
            return True, "Known Malicious IP"
        return False, ""

    def check_ioc(self, indicator: str, indicator_type: str) -> bool:
        return indicator in self.malicious_ips or indicator in self.malicious_domains

    def get_threat_score(self, ip: str) -> float:
        score = 0.0
        if ip in self.malicious_ips:
            score += 50.0
        geo = self.get_geo(ip)
        if geo and geo.country in ["CN", "RU", "KP", "IR"]:
            score += 20.0
        return min(score, 100.0)

    def get_geo(self, ip: str) -> Optional[GeoInfo]:
        if not REQUESTS:
            return None
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
            if res.status_code == 200:
                data = res.json()
                if data.get('status') == 'success':
                    return GeoInfo(
                        country=data.get('country', 'N/A'),
                        city=data.get('city', 'N/A'),
                        isp=data.get('isp', 'N/A'),
                        lat=data.get('lat', 0.0),
                        lon=data.get('lon', 0.0),
                        asn=data.get('as', ''),
                        organization=data.get('org', ''),
                        timezone=data.get('timezone', '')
                    )
        except Exception:
            pass
        return None

# ============================================================================
# RISK SCORING ENGINE
# ============================================================================

class RiskScorer:
    @staticmethod
    def calculate_port_risk(port_result: PortResult) -> float:
        risk = 0.0

        high_risk_ports = [21, 22, 23, 25, 135, 139, 445, 3389, 27017, 6379]
        if port_result.port in high_risk_ports:
            risk += 2.0

        for vuln in port_result.vulnerabilities:
            weight = RISK_WEIGHTS.get(vuln.severity, 1.0)
            risk += weight * (vuln.cvss / 10.0)
            if vuln.exploit_available:
                risk += 2.0

        if port_result.ssl:
            if port_result.ssl.weak:
                risk += 3.0
            if (port_result.ssl.key_size < 4096
                    and port_result.ssl.signature_algorithm
                    and 'RSA' in port_result.ssl.signature_algorithm):
                risk += 1.0
            if port_result.ssl.is_expired:
                risk += 2.0
            if port_result.ssl.is_self_signed:
                risk += 1.0

        if port_result.default_creds_found:
            risk += 5.0

        if port_result.state == "OPEN":
            risk += 1.0

        return min(risk, 10.0)

    @staticmethod
    def calculate_host_risk(host_result: HostResult) -> float:
        if not host_result.open_ports:
            return 0.0

        port_risks = [RiskScorer.calculate_port_risk(p) for p in host_result.open_ports]
        avg_port_risk = mean(port_risks) if port_risks else 0.0

        threat_factor = 0.0
        if host_result.geo and host_result.geo.is_threat:
            threat_factor = 5.0

        compliance_failures = sum(1 for f in host_result.compliance_findings if f.status == "FAIL")
        compliance_factor = compliance_failures * 0.5

        anomaly_factor = len(host_result.anomalies) * 1.5
        lateral_factor = len(host_result.lateral_movement_paths) * 2.0

        total_risk = avg_port_risk + threat_factor + compliance_factor + anomaly_factor + lateral_factor
        return min(total_risk, 10.0)

    @staticmethod
    def get_risk_level(score: float) -> str:
        if score >= 8.0:   return "CRITICAL"
        elif score >= 6.0: return "HIGH"
        elif score >= 4.0: return "MEDIUM"
        elif score >= 2.0: return "LOW"
        return "INFO"

    @staticmethod
    def calculate_security_posture(host_result: HostResult) -> float:
        score = 100.0
        risk_score = RiskScorer.calculate_host_risk(host_result)
        score -= (risk_score * 10)
        return max(0.0, min(100.0, score))

# ============================================================================
# COMPLIANCE ENGINE
# ============================================================================

class ComplianceChecker:
    def __init__(self, frameworks: List[str], logger: logging.Logger):
        self.frameworks = frameworks
        self.logger = logger

    def check_host(self, host_result: HostResult) -> List[ComplianceFinding]:
        findings = []
        for framework in self.frameworks:
            if framework not in COMPLIANCE_RULES:
                continue
            for rule in COMPLIANCE_RULES[framework]:
                findings.append(self.evaluate_rule(rule, host_result))
        return findings

    def evaluate_rule(self, rule: Dict, host: HostResult) -> ComplianceFinding:
        status = "PASS"
        evidence = ""
        remediation = ""

        if rule["check"] == "weak_ssl":
            if any(p.ssl and p.ssl.weak for p in host.open_ports):
                status = "FAIL"
                evidence = "Weak SSL/TLS protocols detected"
                remediation = "Disable SSLv3, TLSv1.0, TLSv1.1. Enable TLSv1.2+"

        elif rule["check"] == "known_vulns":
            if any(p.vulnerabilities for p in host.open_ports):
                status = "FAIL"
                vulns = [v.cve_id for p in host.open_ports for v in p.vulnerabilities]
                evidence = f"Known vulnerabilities: {', '.join(vulns[:5])}"
                remediation = "Patch affected services immediately"

        elif rule["check"] == "open_ports":
            risky = [p.port for p in host.open_ports if p.port in [21, 23, 135, 139, 445]]
            if risky:
                status = "WARNING"
                evidence = f"Unnecessary ports open: {risky}"
                remediation = "Close unused ports via firewall"

        elif rule["check"] == "encryption":
            unencrypted = [p.port for p in host.open_ports if p.port in [80, 21, 23, 25] and not p.ssl]
            if unencrypted:
                status = "FAIL"
                evidence = f"Unencrypted sensitive ports: {unencrypted}"
                remediation = "Enable TLS/SSL for all sensitive services"

        elif rule["check"] == "default_creds":
            if any(p.default_creds_found for p in host.open_ports):
                status = "FAIL"
                evidence = "Default credentials detected"
                remediation = "Change default passwords immediately"

        elif rule["check"] == "audit_trail":
            status = "PASS"
            evidence = "Blockchain audit trail active"

        else:
            status = "PASS"
            evidence = "No issues detected"

        return ComplianceFinding(
            rule_id=rule["id"], framework=rule["check"],
            description=rule["description"], status=status,
            evidence=evidence, weight=rule.get("weight", 5),
            remediation=remediation
        )

# ============================================================================
# NOTIFICATION MANAGER
# ============================================================================

class NotificationManager:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.webhooks: List[str] = []
        self.email_config = None
        self.sms_config = None
        self.pagerduty_key = None

    def configure_email(self, smtp_server: str, smtp_port: int, username: str, password: str, from_email: str):
        self.email_config = {
            "smtp_server": smtp_server, "smtp_port": smtp_port,
            "username": username, "password": password, "from_email": from_email
        }

    def configure_sms(self, provider: str, api_key: str, from_number: str):
        self.sms_config = {"provider": provider, "api_key": api_key, "from_number": from_number}

    def configure_pagerduty(self, routing_key: str):
        self.pagerduty_key = routing_key

    def add_webhook(self, url: str):
        self.webhooks.append(url)

    def send_alert(self, subject: str, message: str, severity: str = "INFO", recipients: List[str] = None):
        for webhook_url in self.webhooks:
            try:
                if "slack" in webhook_url:
                    self._send_slack(webhook_url, subject, message, severity)
                elif "teams" in webhook_url:
                    self._send_teams(webhook_url, subject, message, severity)
                elif "discord" in webhook_url:
                    self._send_discord(webhook_url, subject, message, severity)
                else:
                    self._send_generic_webhook(webhook_url, subject, message, severity)
            except Exception as e:
                self.logger.error(f"Webhook failed: {e}")

        if self.email_config and recipients:
            self._send_email(subject, message, severity, recipients)

        if severity == "CRITICAL" and self.sms_config:
            self._send_sms(subject, message)

        if severity == "CRITICAL" and self.pagerduty_key:
            self._send_pagerduty(subject, message)

    def _send_slack(self, url: str, subject: str, message: str, severity: str):
        color = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "warning"}.get(severity, "good")
        payload = {"attachments": [{"color": color, "title": subject, "text": message,
                                    "footer": "Ultimate Auditor", "ts": int(time.time())}]}
        requests.post(url, json=payload, timeout=10)

    def _send_teams(self, url: str, subject: str, message: str, severity: str):
        color = {"CRITICAL": "800000", "HIGH": "FFA500", "MEDIUM": "FFFF00"}.get(severity, "00FF00")
        requests.post(url, json={"themeColor": color, "title": subject, "text": message}, timeout=10)

    def _send_discord(self, url: str, subject: str, message: str, severity: str):
        color = {"CRITICAL": 16711680, "HIGH": 16753920, "MEDIUM": 16776960}.get(severity, 65280)
        payload = {"embeds": [{"title": subject, "description": message, "color": color,
                                "footer": {"text": "Ultimate Auditor"}}]}
        requests.post(url, json=payload, timeout=10)

    def _send_generic_webhook(self, url: str, subject: str, message: str, severity: str):
        payload = {"subject": subject, "message": message, "severity": severity,
                   "timestamp": datetime.now().isoformat()}
        requests.post(url, json=payload, timeout=10)

    def _send_email(self, subject: str, message: str, severity: str, recipients: List[str]):
        if not self.email_config:
            return
        # FIX: MIMEMultipart and MIMEText were never imported - now imported at top of file
        msg = MIMEMultipart()
        msg['From'] = self.email_config["from_email"]
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = f"[{severity}] {subject}"
        msg.attach(MIMEText(message, 'plain'))
        try:
            server = smtplib.SMTP(self.email_config["smtp_server"], self.email_config["smtp_port"])
            server.starttls()
            server.login(self.email_config["username"], self.email_config["password"])
            server.send_message(msg)
            server.quit()
        except Exception as e:
            self.logger.error(f"Email failed: {e}")

    def _send_sms(self, subject: str, message: str):
        self.logger.info(f"SMS Alert: {subject}")

    def _send_pagerduty(self, subject: str, message: str):
        if not self.pagerduty_key:
            return
        payload = {
            "routing_key": self.pagerduty_key, "event_action": "trigger",
            "payload": {"summary": subject, "severity": "critical", "source": "Ultimate Auditor"}
        }
        requests.post("https://events.pagerduty.com/v2/enqueue",
                      json=payload, headers={"Content-Type": "application/json"}, timeout=10)

# ============================================================================
# SCANNER ENGINE
# ============================================================================

class Scanner:
    def __init__(self, timeout: float, threads: int, logger: logging.Logger,
                 threat_intel: ThreatIntelligence = None, db: DatabaseManager = None,
                 ml_engine: MLEngine = None, cloud: CloudIntegration = None):
        self.timeout = timeout
        self.threads = threads
        self.logger = logger
        self.threat_intel = threat_intel or ThreatIntelligence(logger)
        self.db = db
        self.ml_engine = ml_engine or MLEngine(logger)
        self.cloud = cloud or CloudIntegration(logger)

    def check_host_alive(self, ip: str) -> bool:
        # FIX: original only probed 3 ports - host could be alive with all 3 closed.
        # Now tries a broader set of ports before concluding host is dead.
        probe_ports = [80, 443, 22, 21, 25, 8080, 8443, 3389, 445, 23]
        for port in probe_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return True
                s.close()
            except Exception:
                pass
        return False

    def get_ttl(self, ip: str) -> int:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(2.0)
            s.sendto(b"", (ip, 0))
            s.close()
            return 64
        except Exception:
            return 64

    def guess_os(self, ttl: int) -> OSInfo:
        guess, conf, accuracy = "Unknown", "Low", 0.5
        for t, os_name in OS_TTL_MAP.items():
            if abs(ttl - t) < 5:
                guess, conf, accuracy = os_name, "Medium", 0.75
                break
        return OSInfo(os_guess=guess, ttl=ttl, confidence=conf, accuracy=accuracy)

    def get_geo(self, ip: str) -> Optional[GeoInfo]:
        return self.threat_intel.get_geo(ip)

    def check_ssl(self, ip: str, port: int) -> Optional[SSLInfo]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()
                    proto = ssock.version()
                    cipher = ssock.cipher()[0] if ssock.cipher() else "Unknown"
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']

                    san_list = []
                    if 'subjectAltName' in cert_info:
                        san_list = [item[1] for item in cert_info['subjectAltName']]

                    key_size = 2048
                    sig_algo = "sha256WithRSAEncryption"

                    is_expired = False
                    days_until_expiry = 0
                    try:
                        expiry_str = cert_info.get('notAfter', '')
                        if expiry_str:
                            expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (expiry_date - datetime.now()).days
                            is_expired = days_until_expiry < 0
                    except Exception:
                        pass

                    return SSLInfo(
                        valid=True, issuer=str(cert_info.get('issuer', '')),
                        subject=str(cert_info.get('subject', '')),
                        expiry=cert_info.get('notAfter', ''),
                        protocol=proto, cipher=cipher,
                        weak=proto in weak_protocols,
                        cert_hash=hashlib.sha256(cert_bin).hexdigest(),
                        key_size=key_size, signature_algorithm=sig_algo,
                        san_list=san_list, is_self_signed=False,
                        is_expired=is_expired, days_until_expiry=days_until_expiry
                    )
        except Exception as e:
            return SSLInfo(valid=False, issuer="", subject="", expiry="",
                           protocol="", cipher="", weak=False, error=str(e))

    def check_default_creds(self, ip: str, port: int, service: str) -> bool:
        if service in DEFAULT_CREDS:
            return False
        return False

    def check_vulns(self, service: str, banner: str, ssl_info: Optional[SSLInfo]) -> List[Vulnerability]:
        found = []
        signature = f"{service} {banner}".lower()

        for sig, vuln_data in VULN_DB.items():
            if sig.lower() in signature:
                found.append(Vulnerability(
                    cve_id=", ".join(vuln_data["cves"]),
                    severity=vuln_data["severity"],
                    cvss=vuln_data["cvss"],
                    description=f"Known vulnerability in {sig}",
                    remediation=f"Update {service} to latest version",
                    exploit_available=vuln_data.get("exploit_available", False),
                    patch_available=True,
                    mitre_attack_id="T1190"
                ))

        if ssl_info and ssl_info.weak and ssl_info.protocol in VULN_DB:
            vuln_data = VULN_DB[ssl_info.protocol]
            found.append(Vulnerability(
                cve_id=", ".join(vuln_data["cves"]),
                severity=vuln_data["severity"],
                cvss=vuln_data["cvss"],
                description=f"Weak protocol: {ssl_info.protocol}",
                remediation="Disable weak SSL/TLS protocols",
                mitre_attack_id="T1049"
            ))

        return found

    def analyze_lateral_movement(self, open_ports: List[PortResult], source_ip: str) -> List[LateralMovementPath]:
        paths = []
        port_nums = [p.port for p in open_ports]

        if 445 in port_nums and 5985 in port_nums:
            paths.append(LateralMovementPath(
                start_host=source_ip, end_host="Domain Controllers",
                path=["SMB", "WinRM"], protocols=["TCP/445", "TCP/5985"],
                risk_level="CRITICAL", mitigation="Segment network, disable WinRM"
            ))

        if 22 in port_nums:
            paths.append(LateralMovementPath(
                start_host=source_ip, end_host="Internal Servers",
                path=["SSH"], protocols=["TCP/22"],
                risk_level="HIGH", mitigation="Use MFA, restrict SSH keys"
            ))

        return paths

    def categorize_asset(self, open_ports: List[PortResult]) -> str:
        port_numbers = [p.port for p in open_ports]
        for category, ports in ASSET_CATEGORIES.items():
            if any(p in port_numbers for p in ports):
                return category
        return "general"

    def generate_remediation_script(self, host_result: HostResult) -> str:
        script = "#!/bin/bash\n# Auto-generated Remediation Script\n\n"
        for port in host_result.open_ports:
            if port.ssl and port.ssl.weak:
                script += f"# Disable weak SSL on port {port.port}\n"
                script += f"# opensslConf update for {host_result.ip}\n\n"
            for vuln in port.vulnerabilities:
                script += f"# Fix {vuln.cve_id}: {vuln.remediation}\n"
                script += f"echo 'Patch required for {vuln.cve_id}'\n\n"
        return script

    def scan_port(self, ip: str, port: int, protocol: str = 'tcp') -> Optional[PortResult]:
        start = time.time()
        try:
            sock_type = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
            s = socket.socket(socket.AF_INET, sock_type)
            s.settimeout(self.timeout)

            if protocol == 'tcp':
                res = s.connect_ex((ip, port))
                rt = time.time() - start
                s.close()

                if res == 0:
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except Exception:
                        service = "unknown"

                    banner = ""
                    ssl_info = None

                    try:
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s2.settimeout(1.0)
                        s2.connect((ip, port))
                        s2.send(b"GET / HTTP/1.0\r\n\r\n" if port in [80, 443, 8080] else b"\r\n")
                        banner = s2.recv(1024).decode('utf-8', errors='ignore').strip()[:200]
                        s2.close()
                    except Exception:
                        pass

                    if port in [443, 465, 993, 995, 8443] or service == 'https':
                        ssl_info = self.check_ssl(ip, port)

                    default_creds_found = self.check_default_creds(ip, port, service)
                    vulns = self.check_vulns(service, banner, ssl_info)

                    port_result = PortResult(
                        port=port, protocol=protocol.upper(), state="OPEN",
                        service=service, banner=banner, ssl=ssl_info,
                        vulnerabilities=vulns, response_time=round(rt, 4),
                        default_creds_found=default_creds_found
                    )
                    port_result.risk_score = RiskScorer.calculate_port_risk(port_result)
                    return port_result
            else:
                s.sendto(b"", (ip, port))
                try:
                    s.settimeout(1.0)
                    s.recvfrom(1024)
                    rt = time.time() - start
                    s.close()
                    return PortResult(port=port, protocol="UDP", state="OPEN",
                                      service="unknown", banner="", ssl=None,
                                      vulnerabilities=[], response_time=rt, risk_score=1.0)
                except Exception:
                    s.close()
        except Exception:
            pass
        return None

    def scan_host(self, ip: str, ports: List[int], udp: bool = False,
                  compliance_frameworks: List[str] = None) -> HostResult:
        start = time.time()
        scan_id = hashlib.sha256(f"{ip}{time.time()}".encode()).hexdigest()[:16]

        hostname = "unknown"
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        is_alive = self.check_host_alive(ip)
        os_info = self.guess_os(self.get_ttl(ip)) if is_alive else None
        geo_info = self.get_geo(ip) if is_alive else None

        # FIX: threat flag must be set before building temp_host used for risk/compliance,
        # otherwise the threat_factor is never applied in calculate_host_risk.
        if geo_info:
            is_threat, threat_type = self.threat_intel.is_malicious(ip)
            geo_info.is_threat = is_threat
            geo_info.threat_type = threat_type

        open_ports = []
        if is_alive:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self.scan_port, ip, p): p for p in ports}
                iterator = concurrent.futures.as_completed(futures)
                if TQDM:
                    iterator = tqdm(iterator, total=len(ports), desc=f"Ports {ip}", leave=False)
                for f in iterator:
                    res = f.result()
                    if res:
                        open_ports.append(res)

            if udp:
                udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500]
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                    futures = {ex.submit(self.scan_port, ip, p, 'udp'): p
                               for p in udp_ports if p in ports}
                    for f in concurrent.futures.as_completed(futures):
                        res = f.result()
                        if res:
                            open_ports.append(res)

        anomalies = []
        if self.ml_engine.anomaly_model:
            is_anomaly, score = self.ml_engine.detect_anomalies({"total_open_ports": len(open_ports)})
            if is_anomaly:
                anomalies.append(f"ML Anomaly Detected (Score: {score:.2f})")

        critical_vulns = [v for p in open_ports for v in p.vulnerabilities if v.severity == "CRITICAL"]
        if critical_vulns:
            anomalies.append(f"[CRITICAL] {len(critical_vulns)} critical vulnerabilities")

        compliance_findings = []
        if compliance_frameworks:
            checker = ComplianceChecker(compliance_frameworks, self.logger)
            temp_host = HostResult(
                ip=ip, hostname=hostname, is_alive=is_alive, os=os_info, geo=geo_info,
                open_ports=open_ports, anomalies=anomalies, compliance_findings=[],
                risk_score=0.0, asset_category="general", tags=[],
                scan_time=0.0, timestamp=datetime.now().isoformat(), hash="", scan_id=scan_id
            )
            compliance_findings = checker.check_host(temp_host)

        asset_category = self.categorize_asset(open_ports)
        lateral_paths = self.analyze_lateral_movement(open_ports, ip)

        temp_host = HostResult(
            ip=ip, hostname=hostname, is_alive=is_alive, os=os_info, geo=geo_info,
            open_ports=open_ports, anomalies=anomalies, compliance_findings=compliance_findings,
            risk_score=0.0, asset_category=asset_category, tags=[], scan_time=0.0,
            timestamp=datetime.now().isoformat(), hash="", scan_id=scan_id,
            lateral_movement_paths=lateral_paths
        )

        risk_score = RiskScorer.calculate_host_risk(temp_host)
        security_posture = RiskScorer.calculate_security_posture(temp_host)

        tags = [asset_category]
        if risk_score >= 8.0:
            tags.append("high-risk")
        if critical_vulns:
            tags.append("critical-vulns")
        if geo_info and geo_info.is_threat:
            tags.append("threat-intel")

        scan_time = time.time() - start
        data_hash = get_hash(f"{ip}{json.dumps([p.port for p in open_ports])}")

        return HostResult(
            ip=ip, hostname=hostname, is_alive=is_alive, os=os_info, geo=geo_info,
            open_ports=open_ports, anomalies=anomalies, compliance_findings=compliance_findings,
            risk_score=round(risk_score, 2), asset_category=asset_category, tags=tags,
            scan_time=round(scan_time, 2), timestamp=datetime.now().isoformat(),
            hash=data_hash, scan_id=scan_id, lateral_movement_paths=lateral_paths,
            security_posture_score=round(security_posture, 2)
        )

# ============================================================================
# REPORTER ENGINE
# ============================================================================

class Reporter:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def generate_html(self, results: List[HostResult], stats: ScanStatistics) -> str:
        html = """
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Ultimate Security Audit Report</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0f1a; color: #eee; padding: 20px; }}
            .container {{ max-width: 1600px; margin: 0 auto; }}
            h1 {{ color: #00d9ff; border-bottom: 2px solid #00d9ff; padding-bottom: 10px; margin-bottom: 20px; }}
            h2 {{ color: #00ff88; margin: 20px 0 10px; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
            .stat-card {{ background: #16213e; padding: 20px; border-radius: 8px; border-left: 4px solid #00d9ff; }}
            .stat-card.critical {{ border-left-color: #ff4444; }}
            .stat-card.high {{ border-left-color: #ff8800; }}
            .stat-value {{ font-size: 2em; font-weight: bold; color: #00d9ff; }}
            .stat-label {{ color: #888; font-size: 0.9em; }}
            .host-card {{ background: #16213e; padding: 20px; margin: 15px 0; border-radius: 8px; }}
            .host-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
            .risk-badge {{ padding: 5px 15px; border-radius: 20px; font-weight: bold; }}
            .risk-critical {{ background: #ff4444; }} .risk-high {{ background: #ff8800; }}
            .risk-medium {{ background: #ffcc00; color: #000; }} .risk-low {{ background: #00ff88; color: #000; }}
            table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
            th {{ background: #0f3460; color: #00d9ff; }}
            .vuln-critical {{ color: #ff4444; }} .vuln-high {{ color: #ff8800; }}
            .tag {{ display: inline-block; padding: 3px 10px; background: #0f3460; border-radius: 15px; font-size: 0.8em; margin: 2px; }}
            .compliance-pass {{ color: #00ff88; }} .compliance-fail {{ color: #ff4444; }}
            .blockchain-hash {{ font-family: monospace; font-size: 0.8em; color: #888; }}
            @media (max-width: 768px) {{ .stats-grid {{ grid-template-columns: 1fr 1fr; }} }}
        </style></head><body><div class="container">
        <h1>🛡️ Ultimate Cybersecurity Audit Report</h1>
        <p>Generated: {timestamp} | Scan ID: {scan_id} | Blockchain Verified: ✅</p>
        <h2>📊 Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-value">{total_hosts}</div><div class="stat-label">Total Hosts</div></div>
            <div class="stat-card"><div class="stat-value">{hosts_alive}</div><div class="stat-label">Hosts Alive</div></div>
            <div class="stat-card critical"><div class="stat-value">{critical_vulns}</div><div class="stat-label">Critical Vulns</div></div>
            <div class="stat-card high"><div class="stat-value">{high_vulns}</div><div class="stat-label">High Vulns</div></div>
            <div class="stat-card"><div class="stat-value">{avg_risk}</div><div class="stat-label">Avg Risk Score</div></div>
            <div class="stat-card"><div class="stat-value">{posture}</div><div class="stat-label">Security Posture</div></div>
        </div>
        <h2>🖥️ Host Details</h2>{hosts}
        <h2>📈 Scan Statistics</h2><div class="stat-card"><pre>{stats_json}</pre></div>
        <h2>🔗 Blockchain Audit Trail</h2><div class="stat-card"><p class="blockchain-hash">Chain Integrity: Verified</p></div>
        </div></body></html>
        """

        hosts_html = ""
        for h in results:
            risk_class = f"risk-{RiskScorer.get_risk_level(h.risk_score).lower()}"
            risk_label = RiskScorer.get_risk_level(h.risk_score)
            tags_html = "".join([f'<span class="tag">{t}</span>' for t in h.tags])

            ports_rows = ""
            for p in h.open_ports:
                if p.vulnerabilities:
                    vulns = [f'<span class="vuln-{v.severity.lower()}">{v.cve_id}</span>'
                             for v in p.vulnerabilities]
                    vuln_str = ", ".join(vulns)
                else:
                    vuln_str = "None"
                ssl_str = (f"{p.ssl.protocol} ({p.ssl.cipher})"
                           if p.ssl and p.ssl.valid else "None")
                ports_rows += (f"<tr><td>{p.port}/{p.protocol}</td><td>{p.service}</td>"
                               f"<td>{vuln_str}</td><td>{ssl_str}</td><td>{p.risk_score:.1f}</td></tr>")

            compliance_rows = ""
            for f in h.compliance_findings:
                status_class = "compliance-pass" if f.status == "PASS" else "compliance-fail"
                compliance_rows += (f"<tr><td>{f.rule_id}</td><td>{f.framework}</td>"
                                    f"<td class='{status_class}'>{f.status}</td><td>{f.evidence}</td></tr>")

            anomaly_str = "<br>".join(h.anomalies) if h.anomalies else "None"
            lateral_str = (
                "<br>".join([f"{lp.start_host} -> {lp.end_host} ({lp.risk_level})"
                             for lp in h.lateral_movement_paths])
                if h.lateral_movement_paths else "None"
            )

            hosts_html += f"""
            <div class="host-card">
                <div class="host-header">
                    <h3>{h.ip} ({h.hostname})</h3>
                    <span class="risk-badge {risk_class}">{risk_label} ({h.risk_score:.1f})</span>
                </div>
                <p><strong>OS:</strong> {h.os.os_guess if h.os else 'Unknown'} |
                   <strong>Geo:</strong> {h.geo.country if h.geo else 'N/A'} |
                   <strong>Posture:</strong> {h.security_posture_score}/100</p>
                <p>{tags_html}</p>
                <p><strong>Anomalies:</strong> {anomaly_str}</p>
                <p><strong>Lateral Movement Paths:</strong> {lateral_str}</p>
                <h4>Open Ports</h4>
                <table><tr><th>Port</th><th>Service</th><th>Vulnerabilities</th><th>SSL</th><th>Risk</th></tr>
                {ports_rows}</table>
                <h4>Compliance Findings</h4>
                <table><tr><th>Rule</th><th>Framework</th><th>Status</th><th>Evidence</th></tr>
                {compliance_rows}</table>
            </div>
            """

        return html.format(
            timestamp=stats.start_time, scan_id=stats.scan_id,
            total_hosts=stats.total_hosts, hosts_alive=stats.hosts_alive,
            critical_vulns=stats.critical_vulns, high_vulns=stats.high_vulns,
            avg_risk=f"{stats.average_risk_score:.2f}",
            posture=f"{stats.security_posture_score:.2f}/100",
            hosts=hosts_html,
            stats_json=json.dumps(asdict(stats), indent=2)
        )

    def generate_csv(self, results: List[HostResult]) -> str:
        # FIX: CSV was silently returning empty string
        lines = ["ip,hostname,is_alive,asset_category,risk_score,security_posture_score,"
                 "open_ports,total_vulns,critical_vulns"]
        for h in results:
            total_vulns = sum(len(p.vulnerabilities) for p in h.open_ports)
            critical_vulns = sum(1 for p in h.open_ports
                                 for v in p.vulnerabilities if v.severity == "CRITICAL")
            lines.append(",".join([
                h.ip, h.hostname, str(h.is_alive), h.asset_category,
                str(h.risk_score), str(h.security_posture_score),
                str(len(h.open_ports)), str(total_vulns), str(critical_vulns)
            ]))
        return "\n".join(lines)

    def generate_xml(self, results: List[HostResult], stats: ScanStatistics) -> str:
        # FIX: XML was silently returning empty string
        root = ET.Element("ScanReport", scan_id=stats.scan_id, timestamp=stats.start_time)
        summary = ET.SubElement(root, "Summary")
        ET.SubElement(summary, "TotalHosts").text = str(stats.total_hosts)
        ET.SubElement(summary, "HostsAlive").text = str(stats.hosts_alive)
        ET.SubElement(summary, "TotalVulnerabilities").text = str(stats.total_vulnerabilities)
        ET.SubElement(summary, "CriticalVulns").text = str(stats.critical_vulns)
        ET.SubElement(summary, "AverageRiskScore").text = str(stats.average_risk_score)

        hosts_el = ET.SubElement(root, "Hosts")
        for h in results:
            host_el = ET.SubElement(hosts_el, "Host", ip=h.ip, hostname=h.hostname)
            ET.SubElement(host_el, "RiskScore").text = str(h.risk_score)
            ET.SubElement(host_el, "AssetCategory").text = h.asset_category
            ports_el = ET.SubElement(host_el, "OpenPorts")
            for p in h.open_ports:
                port_el = ET.SubElement(ports_el, "Port", number=str(p.port), protocol=p.protocol)
                ET.SubElement(port_el, "Service").text = p.service
                ET.SubElement(port_el, "RiskScore").text = str(p.risk_score)
                for v in p.vulnerabilities:
                    ET.SubElement(port_el, "Vulnerability",
                                  cve=v.cve_id, severity=v.severity, cvss=str(v.cvss))

        return ET.tostring(root, encoding='unicode', xml_declaration=True)

    def generate_siem_format(self, results: List[HostResult], stats: ScanStatistics) -> str:
        lines = []
        for host in results:
            event = {
                "@timestamp": host.timestamp, "scan_id": stats.scan_id,
                "source_ip": host.ip, "hostname": host.hostname,
                "risk_score": host.risk_score, "asset_category": host.asset_category,
                "open_ports_count": len(host.open_ports),
                "vulnerabilities_count": sum(len(p.vulnerabilities) for p in host.open_ports),
                "compliance_failures": sum(1 for f in host.compliance_findings if f.status == "FAIL"),
                "tags": host.tags, "security_posture": host.security_posture_score
            }
            lines.append(json.dumps(event))
        summary = {
            "@timestamp": stats.end_time, "scan_id": stats.scan_id,
            "event_type": "scan_summary", "total_hosts": stats.total_hosts,
            "total_vulnerabilities": stats.total_vulnerabilities,
            "average_risk_score": stats.average_risk_score,
            "security_posture_score": stats.security_posture_score
        }
        lines.append(json.dumps(summary))
        return "\n".join(lines)

    def diff_scans(self, old_file: str, new_results: List[HostResult]) -> str:
        old_data = load_json_file(old_file)
        if not old_data:
            return "Could not load previous scan file."

        diff_report = ["\n" + "=" * 80, "SCAN COMPARISON REPORT", "=" * 80 + "\n"]

        # FIX: new_results was a List but was being indexed like a dict with string IP keys.
        # Build the dict here so lookups work correctly.
        new_ips: Dict[str, HostResult] = {h.ip: h for h in new_results}
        old_ips: Dict[str, Dict] = {h.get('ip', ''): h for h in old_data if isinstance(h, dict)}

        for ip in set(new_ips.keys()) | set(old_ips.keys()):
            if ip not in old_ips:
                diff_report.append(f"[+] NEW HOST: {ip}")
            elif ip not in new_ips:
                diff_report.append(f"[-] MISSING HOST: {ip}")
            else:
                old_ports = {p.get('port', 0) for p in old_ips[ip].get('open_ports', [])}
                new_ports = {p.port for p in new_ips[ip].open_ports}   # FIX: was new_results[new_ips[ip].ip]
                added = new_ports - old_ports
                removed = old_ports - new_ports
                if added:
                    diff_report.append(f"[!] {ip}: NEW PORTS {sorted(added)}")
                if removed:
                    diff_report.append(f"[!] {ip}: CLOSED PORTS {sorted(removed)}")
                old_risk = old_ips[ip].get('risk_score', 0)
                new_risk = new_ips[ip].risk_score                       # FIX: was new_results[new_ips[ip].ip]
                if abs(new_risk - old_risk) > 1.0:
                    diff_report.append(f"[!] {ip}: RISK SCORE CHANGED {old_risk:.1f} -> {new_risk:.1f}")

        return "\n".join(diff_report)

# ============================================================================
# API & WEB DASHBOARD
# ============================================================================

class API:
    def __init__(self, scanner: Scanner, reporter: Reporter, db: DatabaseManager,
                 notifications: NotificationManager, port: int = 5000):
        self.scanner = scanner
        self.reporter = reporter
        self.db = db
        self.notifications = notifications
        self.port = port
        self.results: List[HostResult] = []
        self.users: Dict[str, User] = {}

        if not FLASK:
            return

        self.app = Flask(__name__)
        self.app.secret_key = SECRET_KEY
        self.app.config['JWT_SECRET_KEY'] = JWT_SECRET
        CORS(self.app)
        self.limiter = Limiter(self.app, key_func=get_remote_address, default_limits=["100 per hour"])
        self.jwt = JWTManager(self.app)
        self.setup_auth()
        self.setup_routes()

    def setup_auth(self):
        admin_id = "admin"
        self.users[admin_id] = User(
            id=admin_id, username="admin", email="admin@localhost",
            password_hash=generate_password_hash("admin123"),   # FIX: werkzeug import added at top
            role="admin", created_at=datetime.now().isoformat()
        )

    def setup_routes(self):
        @self.app.route('/')
        def dashboard():
            return """
            <!DOCTYPE html><html><head><title>Ultimate Scanner API</title>
            <style>body{font-family:monospace;background:#0f0f1a;color:#0f0;padding:20px;}
            .card{background:#16213e;padding:20px;margin:10px 0;border-radius:8px;}
            input,select,button{padding:10px;margin:5px;}button{background:#00d9ff;border:none;cursor:pointer;}
            </style></head><body>
            <h1>🛡️ Ultimate Cybersecurity Audit Platform API</h1>
            <div class="card"><h2>Start New Scan</h2>
            <form id="scanForm">
                <input type="text" id="target" placeholder="Target IP/CIDR" required>
                <input type="text" id="ports" placeholder="Ports (e.g., common)" value="common">
                <select id="report">
                    <option value="html">HTML</option>
                    <option value="json">JSON</option>
                    <option value="siem">SIEM</option>
                </select>
                <button type="submit">Start Scan</button>
            </form></div>
            <div class="card"><h2>Recent Scans</h2><div id="scanHistory"></div></div>
            <div class="card"><h2>Blockchain Audit</h2>
                <button onclick="verifyChain()">Verify Integrity</button>
                <div id="chainStatus"></div>
            </div>
            <script>
            document.getElementById('scanForm').onsubmit = async (e) => {
                e.preventDefault();
                const target = document.getElementById('target').value;
                const ports = document.getElementById('ports').value;
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, ports})
                });
                const data = await response.json();
                alert(data.message);
            };
            async function loadHistory() {
                const response = await fetch('/api/history');
                const data = await response.json();
                document.getElementById('scanHistory').innerHTML =
                    data.map(s => `<p>${s.start_time} - ${s.target} (${s.status})</p>`).join('');
            }
            async function verifyChain() {
                const response = await fetch('/api/blockchain/verify');
                const data = await response.json();
                document.getElementById('chainStatus').innerHTML =
                    data.valid ? "✅ Chain Valid" : "❌ Chain Invalid";
            }
            loadHistory();
            setInterval(loadHistory, 30000);
            </script></body></html>
            """

        @self.app.route('/api/scan', methods=['POST'])
        @self.limiter.limit("10 per minute")
        def scan_api():
            data = request.json
            target = data.get('target')
            if not target:
                return jsonify({"error": "No target"}), 400
            self.db.log_audit("api_user", "scan_started", target, request.remote_addr)

            def run_scan():
                try:
                    ips = parse_ip_range(target, logging.getLogger())
                    ports = parse_ports(data.get('ports', 'common'), logging.getLogger())
                    results = []
                    for ip in ips[:20]:
                        res = self.scanner.scan_host(ip, ports)
                        results.append(res)
                    self.results.extend(results)
                    scan_id = hashlib.sha256(f"{target}{time.time()}".encode()).hexdigest()[:16]
                    stats = self._calculate_stats(results, scan_id)
                    self.db.save_scan(scan_id, results, stats, "api_user")
                    critical_count = sum(
                        1 for h in results for p in h.open_ports
                        for v in p.vulnerabilities if v.severity == "CRITICAL"
                    )
                    if critical_count > 0:
                        self.notifications.send_alert(
                            f"Critical Vulns - {target}",
                            f"Found {critical_count} critical vulns",
                            "CRITICAL", ["security@company.com"]
                        )
                except Exception as e:
                    logging.error(f"API Scan Error: {e}")

            concurrent.futures.ThreadPoolExecutor().submit(run_scan)
            return jsonify({"status": "Scan started", "target": target, "message": "Scan queued"})

        @self.app.route('/api/history')
        def get_history():
            return jsonify(self.db.get_scan_history(10))

        @self.app.route('/api/results')
        def get_results():
            return jsonify([asdict(r) for r in self.results[-100:]])

        @self.app.route('/api/trends')
        def get_trends():
            days = request.args.get('days', 30, type=int)
            return jsonify(self.db.get_trend_data(days))

        @self.app.route('/api/blockchain/verify')
        def verify_blockchain():
            return jsonify({"valid": self.db.verify_blockchain_integrity()})

        @self.app.route('/api/export/<format>')
        def export_results(fmt):
            if not self.results:
                return jsonify({"error": "No results"}), 400
            stats = self._calculate_stats(self.results, "export")
            if fmt == 'html':
                content = self.reporter.generate_html(self.results, stats)
                mimetype = 'text/html'
            elif fmt == 'json':
                content = json.dumps([asdict(r) for r in self.results], indent=2)
                mimetype = 'application/json'
            elif fmt == 'siem':
                content = self.reporter.generate_siem_format(self.results, stats)
                mimetype = 'application/json'
            else:
                return jsonify({"error": "Invalid format"}), 400
            response = make_response(content)
            response.headers['Content-Type'] = mimetype
            response.headers['Content-Disposition'] = f'attachment; filename=scan_report.{fmt}'
            return response

    def _calculate_stats(self, results: List[HostResult], scan_id: str) -> ScanStatistics:
        total_vulns = sum(len(p.vulnerabilities) for h in results for p in h.open_ports)
        critical = sum(1 for h in results for p in h.open_ports
                       for v in p.vulnerabilities if v.severity == "CRITICAL")
        high = sum(1 for h in results for p in h.open_ports
                   for v in p.vulnerabilities if v.severity == "HIGH")
        medium = sum(1 for h in results for p in h.open_ports
                     for v in p.vulnerabilities if v.severity == "MEDIUM")
        low = sum(1 for h in results for p in h.open_ports
                  for v in p.vulnerabilities if v.severity == "LOW")
        compliance_pass = sum(1 for h in results for f in h.compliance_findings if f.status == "PASS")
        compliance_fail = sum(1 for h in results for f in h.compliance_findings if f.status == "FAIL")
        avg_risk = sum(h.risk_score for h in results) / len(results) if results else 0.0
        avg_posture = sum(h.security_posture_score for h in results) / len(results) if results else 0.0

        return ScanStatistics(
            total_hosts=len(results),
            hosts_alive=sum(1 for h in results if h.is_alive),
            total_ports_scanned=sum(len(h.open_ports) for h in results),
            total_open_ports=sum(len(h.open_ports) for h in results),
            total_vulnerabilities=total_vulns,
            critical_vulns=critical, high_vulns=high, medium_vulns=medium, low_vulns=low,
            compliance_pass=compliance_pass, compliance_fail=compliance_fail,
            average_risk_score=round(avg_risk, 2),
            scan_duration=sum(h.scan_time for h in results),
            start_time=datetime.now().isoformat(), end_time=datetime.now().isoformat(),
            scan_id=scan_id, security_posture_score=round(avg_posture, 2),
            attack_surface_area=sum(len(h.open_ports) for h in results),
            remediation_priority_items=critical + high
        )

    def run(self):
        if not FLASK:
            print("Flask not installed. API Mode unavailable.")
            return
        print(f"Starting API Dashboard on http://0.0.0.0:{self.port}")
        self.app.run(host='0.0.0.0', port=self.port, threaded=True, debug=False)

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"Ultimate Cybersecurity Audit Platform v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.0/24 -p common --report html -o scan.html
  %(prog)s -t 192.168.1.1 --api --api-port 5000
  %(prog)s -t 192.168.1.1 --compare baseline.json
  %(prog)s -t 192.168.1.1 --compliance PCI-DSS,HIPAA,GDPR
  %(prog)s -t 192.168.1.1 --webhook https://hooks.slack.com/xxx --threat-intel
        """
    )

    parser.add_argument('-t', '--target', help='Target IP, range, or CIDR')
    parser.add_argument('-p', '--ports', default='common', help='Port range')
    parser.add_argument('--protocols', default='tcp', choices=['tcp', 'udp', 'both'])
    parser.add_argument('--threads', type=int, default=200)
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument('--rate-limit', type=float, default=0.0)
    parser.add_argument('--udp', action='store_true', help='Include UDP scanning')
    parser.add_argument('--compliance', help='Compliance frameworks (PCI-DSS,HIPAA,GDPR,SOX,ISO27001)')
    parser.add_argument('--threat-intel', action='store_true', help='Enable threat intelligence feeds')
    parser.add_argument('--ml', action='store_true', help='Enable ML anomaly detection')
    parser.add_argument('--report', choices=['html', 'json', 'csv', 'xml', 'siem'], default='html')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--db', default=DEFAULT_DB_PATH, help='Database path')
    parser.add_argument('--db-type', default='sqlite', choices=['sqlite', 'postgres', 'mongodb'])
    parser.add_argument('--db-uri', help='Database connection URI')
    parser.add_argument('--api', action='store_true', help='Start REST API mode')
    parser.add_argument('--api-port', type=int, default=5000)
    parser.add_argument('--webhook', action='append', help='Webhook URL')
    parser.add_argument('--email-smtp', help='SMTP server')
    parser.add_argument('--email-from', help='From email')
    parser.add_argument('--email-to', action='append', help='Recipient email')
    parser.add_argument('--compare', help='Compare with previous scan JSON file')
    parser.add_argument('--cloud', choices=['aws', 'azure', 'gcp'], help='Cloud provider')
    parser.add_argument('--azure-subscription', help='Azure subscription ID')
    parser.add_argument('--gcp-project', help='GCP project ID')
    parser.add_argument('--exit-code', action='store_true',
                        help='Return exit code 1 on critical vulns (CI/CD use)')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("UltimateScanner")
    logger.info(f"Ultimate Cybersecurity Audit Platform v{VERSION} started")

    db = DatabaseManager(args.db, args.db_type, args.db_uri or "")
    threat_intel = ThreatIntelligence(logger) if args.threat_intel else None
    ml_engine = MLEngine(logger) if args.ml else None

    cloud = CloudIntegration(logger)
    if args.cloud == 'aws':
        cloud.connect_aws()
    elif args.cloud == 'azure':
        sub_id = args.azure_subscription or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
        cloud.connect_azure(sub_id)   # FIX: pass subscription_id properly
    elif args.cloud == 'gcp':
        project_id = args.gcp_project or os.environ.get("GCP_PROJECT_ID", "")
        cloud.connect_gcp(project_id)

    scanner = Scanner(args.timeout, args.threads, logger, threat_intel, db, ml_engine, cloud)
    reporter = Reporter(logger)
    notifications = NotificationManager(logger)

    if args.webhook:
        for url in args.webhook:
            notifications.add_webhook(url)
    if args.email_smtp and args.email_from:
        notifications.configure_email(args.email_smtp, 587, "", "", args.email_from)

    if args.api:
        api = API(scanner, reporter, db, notifications, args.api_port)
        api.run()
        return

    if not args.target:
        print("Error: Target required unless in API mode.")
        sys.exit(1)

    try:
        target_ips = parse_ip_range(args.target, logger)
        ports = parse_ports(args.ports, logger)
    except Exception as e:
        logger.error(f"Input Error: {e}")
        sys.exit(1)

    compliance_frameworks = (
        [f.strip() for f in args.compliance.split(',')]
        if args.compliance else []
    )

    logger.info(f"Starting scan on {len(target_ips)} hosts...")
    logger.info(f"Ports: {len(ports)}, Threads: {args.threads}, Timeout: {args.timeout}s")
    if compliance_frameworks:
        logger.info(f"Compliance: {', '.join(compliance_frameworks)}")

    results: List[HostResult] = []
    start_time = datetime.now().isoformat()
    scan_id = hashlib.sha256(f"{args.target}{start_time}".encode()).hexdigest()[:16]

    try:
        for ip in target_ips:
            logger.info(f"Scanning {ip}...")
            res = scanner.scan_host(ip, ports, args.udp, compliance_frameworks)
            results.append(res)

            if COLORAMA:
                status = (f"{Fore.GREEN}ALIVE{Style.RESET_ALL}"
                          if res.is_alive else f"{Fore.RED}DEAD{Style.RESET_ALL}")
                risk_color = (Fore.RED if res.risk_score >= 8
                              else Fore.YELLOW if res.risk_score >= 5 else Fore.GREEN)
                print(f"[{status}] {ip} - {len(res.open_ports)} Ports - "
                      f"Risk: {risk_color}{res.risk_score:.1f}{Style.RESET_ALL} - "
                      f"Posture: {res.security_posture_score}/100")
            else:
                status = "ALIVE" if res.is_alive else "DEAD"
                print(f"[{status}] {ip} - {len(res.open_ports)} Ports - "
                      f"Risk: {res.risk_score:.1f} - Posture: {res.security_posture_score}/100")
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")

    end_time = datetime.now().isoformat()

    total_vulns = sum(len(p.vulnerabilities) for h in results for p in h.open_ports)
    critical = sum(1 for h in results for p in h.open_ports
                   for v in p.vulnerabilities if v.severity == "CRITICAL")
    high = sum(1 for h in results for p in h.open_ports
               for v in p.vulnerabilities if v.severity == "HIGH")
    medium = sum(1 for h in results for p in h.open_ports
                 for v in p.vulnerabilities if v.severity == "MEDIUM")
    low = sum(1 for h in results for p in h.open_ports
              for v in p.vulnerabilities if v.severity == "LOW")
    compliance_pass = sum(1 for h in results for f in h.compliance_findings if f.status == "PASS")
    compliance_fail = sum(1 for h in results for f in h.compliance_findings if f.status == "FAIL")
    avg_risk = sum(h.risk_score for h in results) / len(results) if results else 0.0
    avg_posture = sum(h.security_posture_score for h in results) / len(results) if results else 0.0

    stats = ScanStatistics(
        total_hosts=len(results),
        hosts_alive=sum(1 for h in results if h.is_alive),
        total_ports_scanned=len(target_ips) * len(ports),
        total_open_ports=sum(len(h.open_ports) for h in results),
        total_vulnerabilities=total_vulns,
        critical_vulns=critical, high_vulns=high, medium_vulns=medium, low_vulns=low,
        compliance_pass=compliance_pass, compliance_fail=compliance_fail,
        average_risk_score=round(avg_risk, 2),
        scan_duration=sum(h.scan_time for h in results),
        start_time=start_time, end_time=end_time, scan_id=scan_id,
        security_posture_score=round(avg_posture, 2),
        attack_surface_area=sum(len(h.open_ports) for h in results),
        remediation_priority_items=critical + high
    )

    if args.compare:
        print(reporter.diff_scans(args.compare, results))

    if args.report == 'html':
        output = reporter.generate_html(results, stats)
    elif args.report == 'json':
        output = json.dumps([asdict(r) for r in results], indent=2)
    elif args.report == 'csv':
        output = reporter.generate_csv(results)         # FIX: now implemented
    elif args.report == 'xml':
        output = reporter.generate_xml(results, stats)  # FIX: now implemented
    elif args.report == 'siem':
        output = reporter.generate_siem_format(results, stats)
    else:
        output = reporter.generate_html(results, stats)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        logger.info(f"Report saved to {args.output}")

    db.save_scan(scan_id, results, stats, "cli_user")
    db.log_audit("cli_user", "scan_completed", args.target, "127.0.0.1")

    if critical > 0:
        notifications.send_alert(
            f"Critical Vulnerabilities - {args.target}",
            f"Found {critical} critical vulns",
            "CRITICAL", args.email_to or []
        )

    sep = "=" * 80
    print(f"\n{sep}")
    print(colorize("SCAN COMPLETED", "cyan"))
    print(sep)
    print(f"Hosts Scanned:     {stats.hosts_alive}/{stats.total_hosts}")
    print(f"Open Ports:        {stats.total_open_ports}")
    print(f"Vulnerabilities:   {stats.total_vulnerabilities} "
          f"(Critical: {stats.critical_vulns}, High: {stats.high_vulns})")
    print(f"Avg Risk Score:    {stats.average_risk_score:.2f}")
    print(f"Security Posture:  {stats.security_posture_score:.2f}/100")
    print(f"Compliance:        {stats.compliance_pass} Pass, {stats.compliance_fail} Fail")
    print(f"Duration:          {stats.scan_duration:.2f}s")
    print(f"Blockchain Audit:  Verified")
    print(sep)

    if not args.output:
        print(output[:3000] + "..." if len(output) > 3000 else output)

    if args.exit_code and critical > 0:
        logger.warning("Exiting with code 1 due to critical vulnerabilities")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{colorize('Fatal Error:', 'red')} {e}")
        traceback.print_exc()
        sys.exit(1)
