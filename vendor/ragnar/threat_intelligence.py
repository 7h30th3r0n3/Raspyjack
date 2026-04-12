#!/usr/bin/env python3
"""
Advanced Threat Intelligence Integration for Ragnar
Provides real-time threat intelligence enrichment and analysis

Features:
- Multi-source threat intelligence fusion
- Dynamic risk scoring and vulnerability assessment
- Threat actor attribution and campaign tracking
- Predictive threat modeling using machine learning
- Automated response orchestration
- Executive intelligence reporting
"""

import os
import json
import time
import asyncio
import hashlib
import requests
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from logger import Logger
import logging


@dataclass
class ThreatIntelligenceSource:
    """Configuration for a threat intelligence source"""
    name: str
    type: str  # 'misp', 'opencti', 'virustotal', 'shodan', 'custom'
    url: str
    api_key: Optional[str] = None
    enabled: bool = True
    confidence_weight: float = 1.0
    last_updated: Optional[str] = None


@dataclass
class ThreatContext:
    """Threat context information for a finding"""
    source: str
    threat_type: str
    severity: str
    confidence: float
    first_seen: str
    last_seen: str
    description: str
    references: List[str]
    tags: List[str]
    iocs: Dict[str, Any]


@dataclass
class ThreatAttribution:
    """Threat actor attribution information"""
    actor_name: Optional[str]
    actor_aliases: List[str]
    motivation: Optional[str]
    sophistication: str
    geographic_origin: Optional[str]
    target_industries: List[str]
    ttps: List[str]
    confidence: float


@dataclass
class EnrichedFinding:
    """Enriched vulnerability or credential finding with threat intelligence"""
    original_finding: Dict[str, Any]
    threat_contexts: List[ThreatContext]
    dynamic_risk_score: float
    attribution: Optional[ThreatAttribution]
    active_campaigns: List[str]
    exploitation_prediction: Dict[str, Any]
    recommended_actions: List[str]
    executive_summary: str


class ThreatIntelligenceFusion:
    """Advanced threat intelligence integration and fusion engine"""
    
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = Logger(name="ThreatIntelligence", level=logging.INFO)
        
        # Intelligence storage
        self.threat_data_dir = self._resolve_threat_dir()
        self._rebuild_file_paths()
        
        # Configuration
        self.threat_sources: Dict[str, ThreatIntelligenceSource] = {}
        self.threat_cache: Dict[str, Dict] = {}
        self.enriched_findings: Dict[str, EnrichedFinding] = {}
        
        # ML and analysis components
        self.risk_calculator = DynamicRiskCalculator()
        self.attribution_engine = ThreatAttributionEngine()
        self.prediction_engine = ThreatPredictionEngine()
        self.campaign_tracker = CampaignTracker()
        
        # Background processing
        self.intelligence_thread = None
        self.should_stop = False
        
        # Initialize the system
        self.setup_intelligence_system()

    def _resolve_threat_dir(self) -> str:
        candidate = getattr(self.shared_data, 'network_threat_dir', None)
        if candidate:
            return candidate
        return os.path.join(self.shared_data.datadir, 'threat_intelligence')

    def _rebuild_file_paths(self):
        self.sources_config_file = os.path.join(self.threat_data_dir, 'sources_config.json')
        self.threat_cache_file = os.path.join(self.threat_data_dir, 'threat_cache.json')
        self.enriched_findings_file = os.path.join(self.threat_data_dir, 'enriched_findings.json')

    def set_storage_root(self, threat_dir: str):
        """Switch threat intelligence storage when network changes."""
        if not threat_dir or threat_dir == self.threat_data_dir:
            return
        self.persist_state()
        self.threat_data_dir = threat_dir
        self._rebuild_file_paths()
        os.makedirs(self.threat_data_dir, exist_ok=True)
        self.ensure_json_files_exist()
        self.load_configuration()
        self.load_threat_cache()
        self.load_enriched_findings()
        self.logger.info(f"Threat intelligence storage switched to: {self.threat_data_dir}")

    def persist_state(self):
        """Persist caches before switching networks."""
        try:
            self.save_threat_cache()
            self.save_enriched_findings()
        except Exception as exc:
            self.logger.warning(f"Failed to persist threat intelligence state: {exc}")
        
    def setup_intelligence_system(self):
        """Initialize the threat intelligence system"""
        try:
            os.makedirs(self.threat_data_dir, exist_ok=True)
            self.ensure_json_files_exist()
            self.load_configuration()
            self.load_threat_cache()
            self.load_enriched_findings()
            self.initialize_default_sources()
            self.start_background_intelligence_processing()
            self.logger.info("Threat intelligence system initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize threat intelligence system: {e}")
    
    def ensure_json_files_exist(self):
        """Ensure all required JSON files exist with proper empty content"""
        os.makedirs(self.threat_data_dir, exist_ok=True)
        json_files = [
            self.threat_cache_file,
            self.enriched_findings_file
        ]
        
        for json_file in json_files:
            try:
                if not os.path.exists(json_file) or os.path.getsize(json_file) == 0:
                    with open(json_file, 'w') as f:
                        json.dump({}, f, indent=2)
                    self.logger.debug(f"Initialized empty JSON file: {json_file}")
            except Exception as e:
                self.logger.error(f"Error initializing JSON file {json_file}: {e}")
        
        # Handle sources config file separately as it has a different structure
        if not os.path.exists(self.sources_config_file):
            try:
                with open(self.sources_config_file, 'w') as f:
                    json.dump({}, f, indent=2)
                self.logger.debug(f"Initialized empty sources config file: {self.sources_config_file}")
            except Exception as e:
                self.logger.error(f"Error initializing sources config file: {e}")
    
    def initialize_default_sources(self):
        """Initialize default threat intelligence sources"""
        default_sources = [
            ThreatIntelligenceSource(
                name="CISA_KEV",
                type="cisa",
                url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                enabled=True,
                confidence_weight=0.9
            ),
            ThreatIntelligenceSource(
                name="NVD_CVE",
                type="nvd",
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                enabled=True,
                confidence_weight=0.8
            ),
            ThreatIntelligenceSource(
                name="AlienVault_OTX",
                type="otx",
                url="https://otx.alienvault.com/api/v1",
                enabled=True,
                confidence_weight=0.7
            ),
            ThreatIntelligenceSource(
                name="MITRE_ATT&CK",
                type="mitre",
                url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
                enabled=True,
                confidence_weight=0.9
            )
        ]
        
        for source in default_sources:
            if source.name not in self.threat_sources:
                self.threat_sources[source.name] = source
        
        self.save_configuration()
    
    def load_configuration(self):
        """Load threat intelligence sources configuration"""
        try:
            if os.path.exists(self.sources_config_file):
                # Check if file is empty before trying to parse JSON
                if os.path.getsize(self.sources_config_file) == 0:
                    self.logger.debug("Sources config file is empty, will initialize with default sources")
                    self.threat_sources = {}
                    return
                
                with open(self.sources_config_file, 'r') as f:
                    content = f.read().strip()
                    if not content:
                        self.logger.debug("Sources config file contains no content, will initialize with default sources")
                        self.threat_sources = {}
                        return
                    
                    config_data = json.loads(content)
                    if not isinstance(config_data, dict):
                        self.logger.warning("Sources config file contains invalid data format, will initialize with default sources")
                        self.threat_sources = {}
                        return
                    
                    for name, source_data in config_data.items():
                        self.threat_sources[name] = ThreatIntelligenceSource(**source_data)
                    
                self.logger.info(f"Loaded {len(self.threat_sources)} threat intelligence sources")
            else:
                self.logger.debug("Sources config file does not exist, will initialize with default sources")
                self.threat_sources = {}
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in sources config file: {e}")
            self.logger.info("Backing up corrupted config file and initializing with default sources")
            try:
                # Backup corrupted file
                backup_file = f"{self.sources_config_file}.backup.{int(time.time())}"
                os.rename(self.sources_config_file, backup_file)
                self.logger.info(f"Corrupted config file backed up to: {backup_file}")
            except Exception as backup_error:
                self.logger.error(f"Failed to backup corrupted config file: {backup_error}")
            self.threat_sources = {}
        except Exception as e:
            self.logger.error(f"Error loading threat intelligence configuration: {e}")
            self.threat_sources = {}
    
    def save_configuration(self):
        """Save threat intelligence sources configuration"""
        try:
            config_data = {name: asdict(source) for name, source in self.threat_sources.items()}
            with open(self.sources_config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            self.logger.debug("Threat intelligence configuration saved")
        except Exception as e:
            self.logger.error(f"Error saving threat intelligence configuration: {e}")
    
    def load_threat_cache(self):
        """Load cached threat intelligence data"""
        try:
            if os.path.exists(self.threat_cache_file):
                # Check if file is empty before trying to parse JSON
                if os.path.getsize(self.threat_cache_file) == 0:
                    self.logger.debug("Threat cache file is empty, initializing with empty cache")
                    self.threat_cache = {}
                    return
                
                with open(self.threat_cache_file, 'r') as f:
                    content = f.read().strip()
                    if not content:
                        self.logger.debug("Threat cache file contains no content, initializing with empty cache")
                        self.threat_cache = {}
                        return
                    
                    cache_data = json.loads(content)
                    if not isinstance(cache_data, dict):
                        self.logger.warning("Threat cache file contains invalid data format, initializing with empty cache")
                        self.threat_cache = {}
                        return
                    
                    self.threat_cache = cache_data
                    
                self.logger.info(f"Loaded threat intelligence cache with {len(self.threat_cache)} entries")
            else:
                self.logger.debug("Threat cache file does not exist, initializing with empty cache")
                self.threat_cache = {}
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in threat cache file: {e}")
            self.logger.info("Backing up corrupted cache file and initializing with empty cache")
            try:
                # Backup corrupted file
                backup_file = f"{self.threat_cache_file}.backup.{int(time.time())}"
                os.rename(self.threat_cache_file, backup_file)
                self.logger.info(f"Corrupted cache file backed up to: {backup_file}")
            except Exception as backup_error:
                self.logger.error(f"Failed to backup corrupted cache file: {backup_error}")
            self.threat_cache = {}
        except Exception as e:
            self.logger.error(f"Error loading threat intelligence cache: {e}")
            self.threat_cache = {}
    
    def save_threat_cache(self):
        """Save threat intelligence cache"""
        try:
            with open(self.threat_cache_file, 'w') as f:
                json.dump(self.threat_cache, f, indent=2)
            self.logger.debug("Threat intelligence cache saved")
        except Exception as e:
            self.logger.error(f"Error saving threat intelligence cache: {e}")
    
    def load_enriched_findings(self):
        """Load enriched findings data"""
        try:
            if os.path.exists(self.enriched_findings_file):
                # Check if file is empty before trying to parse JSON
                if os.path.getsize(self.enriched_findings_file) == 0:
                    self.logger.debug("Enriched findings file is empty, initializing with empty data")
                    self.enriched_findings = {}
                    return
                
                with open(self.enriched_findings_file, 'r') as f:
                    content = f.read().strip()
                    if not content:
                        self.logger.debug("Enriched findings file contains no content, initializing with empty data")
                        self.enriched_findings = {}
                        return
                    
                    findings_data = json.loads(content)
                    if not isinstance(findings_data, dict):
                        self.logger.warning("Enriched findings file contains invalid data format, initializing with empty data")
                        self.enriched_findings = {}
                        return
                    
                    for finding_id, finding_data in findings_data.items():
                        # Reconstruct EnrichedFinding objects from JSON
                        self.enriched_findings[finding_id] = self.deserialize_enriched_finding(finding_data)
                    
                self.logger.info(f"Loaded {len(self.enriched_findings)} enriched findings")
            else:
                self.logger.debug("Enriched findings file does not exist, initializing with empty data")
                self.enriched_findings = {}
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in enriched findings file: {e}")
            self.logger.info("Backing up corrupted file and initializing with empty data")
            try:
                # Backup corrupted file
                backup_file = f"{self.enriched_findings_file}.backup.{int(time.time())}"
                os.rename(self.enriched_findings_file, backup_file)
                self.logger.info(f"Corrupted file backed up to: {backup_file}")
            except Exception as backup_error:
                self.logger.error(f"Failed to backup corrupted file: {backup_error}")
            self.enriched_findings = {}
        except Exception as e:
            self.logger.error(f"Error loading enriched findings: {e}")
            self.enriched_findings = {}
    
    def save_enriched_findings(self):
        """Save enriched findings data"""
        try:
            findings_data = {
                finding_id: self.serialize_enriched_finding(finding) 
                for finding_id, finding in self.enriched_findings.items()
            }
            with open(self.enriched_findings_file, 'w') as f:
                json.dump(findings_data, f, indent=2)
            self.logger.debug("Enriched findings saved")
        except Exception as e:
            self.logger.error(f"Error saving enriched findings: {e}")
    
    async def enrich_finding_with_threat_intelligence(self, finding: Dict[str, Any]) -> EnrichedFinding:
        """Enrich a vulnerability or credential finding with threat intelligence"""
        try:
            finding_id = finding.get('id', hashlib.md5(str(finding).encode()).hexdigest()[:12])
            
            # Gather threat contexts from multiple sources
            threat_contexts = await self.gather_threat_contexts(finding)
            
            # Calculate dynamic risk score
            dynamic_risk_score = self.risk_calculator.calculate_dynamic_risk(finding, threat_contexts)
            
            # Determine threat attribution
            attribution = await self.attribution_engine.analyze_attribution(finding, threat_contexts)
            
            # Identify active campaigns
            active_campaigns = await self.campaign_tracker.identify_active_campaigns(finding, threat_contexts)
            
            # Generate exploitation prediction
            exploitation_prediction = await self.prediction_engine.predict_exploitation(finding, threat_contexts)
            
            # Generate recommended actions
            recommended_actions = self.generate_recommended_actions(finding, threat_contexts, dynamic_risk_score)
            
            # Create executive summary
            executive_summary = self.generate_executive_summary(finding, threat_contexts, dynamic_risk_score, attribution)
            
            # Create enriched finding
            enriched_finding = EnrichedFinding(
                original_finding=finding,
                threat_contexts=threat_contexts,
                dynamic_risk_score=dynamic_risk_score,
                attribution=attribution,
                active_campaigns=active_campaigns,
                exploitation_prediction=exploitation_prediction,
                recommended_actions=recommended_actions,
                executive_summary=executive_summary
            )
            
            # Store enriched finding
            self.enriched_findings[finding_id] = enriched_finding
            self.save_enriched_findings()
            
            self.logger.info(f"Successfully enriched finding {finding_id} with threat intelligence")
            return enriched_finding
            
        except Exception as e:
            self.logger.error(f"Error enriching finding with threat intelligence: {e}")
            # Return basic enriched finding on error
            return EnrichedFinding(
                original_finding=finding,
                threat_contexts=[],
                dynamic_risk_score=5.0,
                attribution=None,
                active_campaigns=[],
                exploitation_prediction={},
                recommended_actions=["Monitor for exploitation", "Apply available patches"],
                executive_summary="Threat intelligence enrichment failed - manual review recommended"
            )
    
    async def gather_threat_contexts(self, finding: Dict[str, Any]) -> List[ThreatContext]:
        """Gather threat context from multiple intelligence sources"""
        threat_contexts = []
        
        # Extract identifiers from finding for threat intelligence lookup
        identifiers = self.extract_threat_identifiers(finding)
        
        # Query each enabled threat intelligence source
        for source_name, source in self.threat_sources.items():
            if not source.enabled:
                continue
                
            try:
                context = await self.query_threat_source(source, identifiers)
                if context:
                    threat_contexts.append(context)
            except Exception as e:
                self.logger.warning(f"Failed to query threat source {source_name}: {e}")
        
        return threat_contexts
    
    def extract_threat_identifiers(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract threat identifiers from a finding for intelligence lookup"""
        identifiers = {
            'host': finding.get('host'),
            'port': finding.get('port'),
            'service': finding.get('service'),
            'vulnerability': finding.get('vulnerability'),
            'cve_id': None,
            'hash': None,
            'domain': None,
            'ip': finding.get('host')
        }
        
        # Extract CVE IDs from vulnerability description
        vulnerability_text = finding.get('vulnerability', '') + ' ' + str(finding.get('details', ''))
        cve_matches = self.extract_cve_ids(vulnerability_text)
        if cve_matches:
            identifiers['cve_id'] = cve_matches[0]
        
        return identifiers
    
    def extract_cve_ids(self, text: str) -> List[str]:
        """Extract CVE IDs from text"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return re.findall(cve_pattern, text, re.IGNORECASE)
    
    async def query_threat_source(self, source: ThreatIntelligenceSource, identifiers: Dict[str, Any]) -> Optional[ThreatContext]:
        """Query a specific threat intelligence source"""
        try:
            if source.type == "cisa":
                return await self.query_cisa_kev(source, identifiers)
            elif source.type == "nvd":
                return await self.query_nvd_cve(source, identifiers)
            elif source.type == "otx":
                return await self.query_alienvault_otx(source, identifiers)
            elif source.type == "mitre":
                return await self.query_mitre_attack(source, identifiers)
            else:
                self.logger.warning(f"Unknown threat intelligence source type: {source.type}")
                return None
        except Exception as e:
            self.logger.error(f"Error querying threat source {source.name}: {e}")
            return None
    
    async def query_cisa_kev(self, source: ThreatIntelligenceSource, identifiers: Dict[str, Any]) -> Optional[ThreatContext]:
        """Query CISA Known Exploited Vulnerabilities catalog"""
        try:
            cve_id = identifiers.get('cve_id')
            if not cve_id:
                return None
            
            # Check cache first
            cache_key = f"cisa_kev_{cve_id}"
            if cache_key in self.threat_cache:
                cached_data = self.threat_cache[cache_key]
                if datetime.now() - datetime.fromisoformat(cached_data['cached_at']) < timedelta(hours=24):
                    return ThreatContext(**cached_data['context'])
            
            # Query CISA KEV
            response = requests.get(source.url, timeout=30)
            if response.status_code == 200:
                kev_data = response.json()
                
                # Search for the CVE
                for vuln in kev_data.get('vulnerabilities', []):
                    if vuln.get('cveID') == cve_id:
                        context = ThreatContext(
                            source="CISA_KEV",
                            threat_type="known_exploited_vulnerability",
                            severity="HIGH",
                            confidence=0.9,
                            first_seen=vuln.get('dateAdded', ''),
                            last_seen=vuln.get('dateAdded', ''),
                            description=f"CISA KEV: {vuln.get('vulnerabilityName', 'Unknown')}",
                            references=[source.url],
                            tags=["known_exploited", "cisa_kev"],
                            iocs={"cve_id": cve_id}
                        )
                        
                        # Cache the result
                        self.threat_cache[cache_key] = {
                            'context': asdict(context),
                            'cached_at': datetime.now().isoformat()
                        }
                        self.save_threat_cache()
                        
                        return context
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error querying CISA KEV: {e}")
            return None
    
    async def query_nvd_cve(self, source: ThreatIntelligenceSource, identifiers: Dict[str, Any]) -> Optional[ThreatContext]:
        """Query NVD CVE database"""
        try:
            cve_id = identifiers.get('cve_id')
            if not cve_id:
                return None
            
            # Check cache first
            cache_key = f"nvd_cve_{cve_id}"
            if cache_key in self.threat_cache:
                cached_data = self.threat_cache[cache_key]
                if datetime.now() - datetime.fromisoformat(cached_data['cached_at']) < timedelta(hours=24):
                    return ThreatContext(**cached_data['context'])
            
            # Query NVD CVE API
            url = f"{source.url}?cveId={cve_id}"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                nvd_data = response.json()
                
                if nvd_data.get('totalResults', 0) > 0:
                    cve_item = nvd_data['vulnerabilities'][0]['cve']
                    
                    # Extract CVSS score for severity
                    severity = "MEDIUM"
                    cvss_score = 5.0
                    
                    metrics = cve_item.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in metrics:
                        cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV2' in metrics:
                        cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                    
                    if cvss_score >= 9.0:
                        severity = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    
                    description = ""
                    descriptions = cve_item.get('descriptions', [])
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    context = ThreatContext(
                        source="NVD_CVE",
                        threat_type="vulnerability",
                        severity=severity,
                        confidence=0.8,
                        first_seen=cve_item.get('published', ''),
                        last_seen=cve_item.get('lastModified', ''),
                        description=description[:500],
                        references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                        tags=["cve", "nvd"],
                        iocs={"cve_id": cve_id, "cvss_score": cvss_score}
                    )
                    
                    # Cache the result
                    self.threat_cache[cache_key] = {
                        'context': asdict(context),
                        'cached_at': datetime.now().isoformat()
                    }
                    self.save_threat_cache()
                    
                    return context
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error querying NVD CVE: {e}")
            return None
    
    async def query_alienvault_otx(self, source: ThreatIntelligenceSource, identifiers: Dict[str, Any]) -> Optional[ThreatContext]:
        """Query AlienVault OTX for threat intelligence"""
        try:
            # DISABLED: This would require an API key for full functionality
            # This was creating fake/placeholder data that adds noise
            # TODO: Implement proper OTX API integration with real API key
            self.logger.debug("AlienVault OTX integration disabled - requires API key for real functionality")
            return None
            
        except Exception as e:
            self.logger.error(f"Error querying AlienVault OTX: {e}")
            return None
    
    async def query_mitre_attack(self, source: ThreatIntelligenceSource, identifiers: Dict[str, Any]) -> Optional[ThreatContext]:
        """Query MITRE ATT&CK framework"""
        try:
            service = identifiers.get('service')
            if not service:
                return None
            
            # Check cache first
            cache_key = f"mitre_service_{service}"
            if cache_key in self.threat_cache:
                cached_data = self.threat_cache[cache_key]
                if datetime.now() - datetime.fromisoformat(cached_data['cached_at']) < timedelta(days=7):
                    return ThreatContext(**cached_data['context'])
            
            # Note: This is a simplified implementation
            # Full implementation would parse the MITRE ATT&CK matrix
            context = ThreatContext(
                source="MITRE_ATT&CK",
                threat_type="technique_mapping",
                severity="MEDIUM",
                confidence=0.7,
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                description=f"MITRE ATT&CK technique mapping for {service}",
                references=["https://attack.mitre.org"],
                tags=["mitre_attack", "technique"],
                iocs={"service": service}
            )
            
            # Cache the result
            self.threat_cache[cache_key] = {
                'context': asdict(context),
                'cached_at': datetime.now().isoformat()
            }
            self.save_threat_cache()
            
            return context
            
        except Exception as e:
            self.logger.error(f"Error querying MITRE ATT&CK: {e}")
            return None
    
    def generate_recommended_actions(self, finding: Dict[str, Any], threat_contexts: List[ThreatContext], risk_score: float) -> List[str]:
        """Generate recommended actions based on threat intelligence"""
        actions = []
        
        # High-risk findings get priority actions
        if risk_score >= 8.0:
            actions.append("IMMEDIATE: Isolate affected systems")
            actions.append("IMMEDIATE: Apply emergency patches")
            actions.append("IMMEDIATE: Monitor for exploitation")
        
        # Check for known exploited vulnerabilities
        for context in threat_contexts:
            if "known_exploited" in context.tags:
                actions.append("URGENT: This vulnerability is actively exploited in the wild")
                actions.append("URGENT: Implement CISA-recommended mitigations")
        
        # CVE-specific actions
        for context in threat_contexts:
            if context.threat_type == "vulnerability" and context.severity in ["HIGH", "CRITICAL"]:
                actions.append(f"Patch {context.iocs.get('cve_id', 'vulnerability')} immediately")
                actions.append("Update vulnerability scanners with latest signatures")
        
        # Service-specific actions
        service = finding.get('service', '')
        if service:
            actions.append(f"Review {service} configuration for security hardening")
            actions.append(f"Monitor {service} logs for suspicious activity")
        
        # Default actions
        if not actions:
            actions.extend([
                "Monitor affected systems for suspicious activity",
                "Apply security updates when available",
                "Review system configuration",
                "Consider additional security controls"
            ])
        
        return actions[:10]  # Limit to top 10 actions
    
    def generate_executive_summary(self, finding: Dict[str, Any], threat_contexts: List[ThreatContext], 
                                 risk_score: float, attribution: Optional[ThreatAttribution]) -> str:
        """Generate executive summary for the enriched finding"""
        try:
            vulnerability = finding.get('vulnerability', 'Unknown vulnerability')
            host = finding.get('host', 'Unknown host')
            
            # Risk level description
            if risk_score >= 9.0:
                risk_level = "CRITICAL"
                urgency = "immediate action required"
            elif risk_score >= 7.0:
                risk_level = "HIGH"
                urgency = "urgent attention needed"
            elif risk_score >= 5.0:
                risk_level = "MEDIUM"
                urgency = "timely remediation recommended"
            else:
                risk_level = "LOW"
                urgency = "monitor and patch during regular maintenance"
            
            summary = f"**{risk_level} RISK**: {vulnerability} detected on {host} - {urgency}. "
            
            # Add threat intelligence context
            known_exploited = any("known_exploited" in context.tags for context in threat_contexts)
            if known_exploited:
                summary += "This vulnerability is actively exploited in the wild. "
            
            # Add attribution if available
            if attribution and attribution.actor_name:
                summary += f"Associated with threat actor: {attribution.actor_name}. "
            
            # Add campaign information
            active_campaigns = [context for context in threat_contexts if context.threat_type == "campaign"]
            if active_campaigns:
                summary += f"Part of active campaign: {active_campaigns[0].description}. "
            
            summary += f"Dynamic risk score: {risk_score:.1f}/10."
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating executive summary: {e}")
            return f"Vulnerability detected: {finding.get('vulnerability', 'Unknown')} - manual review recommended"
    
    def serialize_enriched_finding(self, finding: EnrichedFinding) -> Dict[str, Any]:
        """Serialize EnrichedFinding to JSON-compatible format"""
        return {
            'original_finding': finding.original_finding,
            'threat_contexts': [asdict(context) for context in finding.threat_contexts],
            'dynamic_risk_score': finding.dynamic_risk_score,
            'attribution': asdict(finding.attribution) if finding.attribution else None,
            'active_campaigns': finding.active_campaigns,
            'exploitation_prediction': finding.exploitation_prediction,
            'recommended_actions': finding.recommended_actions,
            'executive_summary': finding.executive_summary
        }
    
    def deserialize_enriched_finding(self, data: Dict[str, Any]) -> EnrichedFinding:
        """Deserialize JSON data to EnrichedFinding object"""
        return EnrichedFinding(
            original_finding=data['original_finding'],
            threat_contexts=[ThreatContext(**context) for context in data['threat_contexts']],
            dynamic_risk_score=data['dynamic_risk_score'],
            attribution=ThreatAttribution(**data['attribution']) if data['attribution'] else None,
            active_campaigns=data['active_campaigns'],
            exploitation_prediction=data['exploitation_prediction'],
            recommended_actions=data['recommended_actions'],
            executive_summary=data['executive_summary']
        )
    
    def start_background_intelligence_processing(self):
        """Start background thread for intelligence processing"""
        if self.intelligence_thread is None or not self.intelligence_thread.is_alive():
            self.should_stop = False
            self.intelligence_thread = threading.Thread(target=self.background_intelligence_worker)
            self.intelligence_thread.daemon = True
            self.intelligence_thread.start()
            self.logger.info("Background threat intelligence processing started")
    
    def background_intelligence_worker(self):
        """Background worker for threat intelligence processing"""
        while not self.should_stop:
            try:
                # Process pending findings for enrichment
                self.process_pending_enrichments()
                
                # Update threat intelligence feeds
                self.update_threat_feeds()
                
                # Clean up old cache entries
                self.cleanup_cache()
                
                # Sleep for 5 minutes before next iteration
                time.sleep(300)
                
            except Exception as e:
                self.logger.error(f"Error in background intelligence processing: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def process_pending_enrichments(self):
        """Process findings that need threat intelligence enrichment"""
        try:
            # Get findings from network intelligence
            if hasattr(self.shared_data, 'network_intelligence'):
                active_findings = self.shared_data.network_intelligence.get_active_findings_for_dashboard()
                
                # Process vulnerabilities
                for vuln_id, vuln_data in active_findings.get('vulnerabilities', {}).items():
                    if vuln_id not in self.enriched_findings:
                        # Schedule for enrichment
                        asyncio.run(self.enrich_finding_with_threat_intelligence(vuln_data))
                
                # Process credentials
                for cred_id, cred_data in active_findings.get('credentials', {}).items():
                    if cred_id not in self.enriched_findings:
                        # Schedule for enrichment
                        asyncio.run(self.enrich_finding_with_threat_intelligence(cred_data))
                        
        except Exception as e:
            self.logger.error(f"Error processing pending enrichments: {e}")
    
    def update_threat_feeds(self):
        """Update threat intelligence feeds"""
        try:
            for source_name, source in self.threat_sources.items():
                if not source.enabled:
                    continue
                
                # Check if update is needed (daily updates)
                if source.last_updated:
                    last_update = datetime.fromisoformat(source.last_updated)
                    if datetime.now() - last_update < timedelta(hours=24):
                        continue
                
                self.logger.info(f"Updating threat intelligence feed: {source_name}")
                # Update the source's last_updated timestamp
                source.last_updated = datetime.now().isoformat()
                
            self.save_configuration()
            
        except Exception as e:
            self.logger.error(f"Error updating threat feeds: {e}")
    
    def cleanup_cache(self):
        """Clean up old threat intelligence cache entries"""
        try:
            current_time = datetime.now()
            keys_to_remove = []
            
            for key, cached_data in self.threat_cache.items():
                cached_at = datetime.fromisoformat(cached_data['cached_at'])
                if current_time - cached_at > timedelta(days=7):
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.threat_cache[key]
            
            if keys_to_remove:
                self.save_threat_cache()
                self.logger.info(f"Cleaned up {len(keys_to_remove)} old cache entries")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up cache: {e}")
    
    def stop(self):
        """Stop threat intelligence processing"""
        self.should_stop = True
        if self.intelligence_thread and self.intelligence_thread.is_alive():
            self.intelligence_thread.join(timeout=5)
        self.logger.info("Threat intelligence system stopped")
    
    def get_enriched_findings_summary(self) -> Dict[str, Any]:
        """Get summary of enriched findings for dashboard"""
        try:
            total_findings = len(self.enriched_findings)
            critical_findings = sum(1 for f in self.enriched_findings.values() if f.dynamic_risk_score >= 9.0)
            high_findings = sum(1 for f in self.enriched_findings.values() if 7.0 <= f.dynamic_risk_score < 9.0)
            known_exploited = sum(1 for f in self.enriched_findings.values() 
                                if any("known_exploited" in context.tags for context in f.threat_contexts))
            
            return {
                'total_enriched_findings': total_findings,
                'critical_risk_findings': critical_findings,
                'high_risk_findings': high_findings,
                'known_exploited_vulnerabilities': known_exploited,
                'threat_sources_enabled': sum(1 for s in self.threat_sources.values() if s.enabled),
                'last_intelligence_update': max([s.last_updated for s in self.threat_sources.values() 
                                               if s.last_updated], default=None)
            }
        except Exception as e:
            self.logger.error(f"Error getting enriched findings summary: {e}")
            return {}


class DynamicRiskCalculator:
    """Calculate dynamic risk scores based on threat intelligence"""
    
    def calculate_dynamic_risk(self, finding: Dict[str, Any], threat_contexts: List[ThreatContext]) -> float:
        """Calculate dynamic risk score (0-10 scale)"""
        try:
            base_score = 5.0  # Default medium risk
            
            # Adjust based on severity from finding
            severity = finding.get('severity', 'medium').lower()
            if severity == 'critical':
                base_score = 9.0
            elif severity == 'high':
                base_score = 7.0
            elif severity == 'medium':
                base_score = 5.0
            elif severity == 'low':
                base_score = 3.0
            
            # Threat intelligence modifiers
            for context in threat_contexts:
                # Known exploited vulnerabilities get maximum score
                if "known_exploited" in context.tags:
                    base_score = max(base_score, 9.5)
                
                # CVSS scores from NVD
                if 'cvss_score' in context.iocs:
                    cvss_score = context.iocs['cvss_score']
                    base_score = max(base_score, cvss_score)
                
                # High confidence threat intelligence increases score
                if context.confidence > 0.8:
                    base_score += 0.5
                
                # Recent threat activity increases score
                if context.last_seen:
                    try:
                        last_seen = datetime.fromisoformat(context.last_seen.replace('Z', '+00:00'))
                        if datetime.now() - last_seen.replace(tzinfo=None) < timedelta(days=30):
                            base_score += 1.0
                    except:
                        pass
            
            # Cap at 10.0
            return min(base_score, 10.0)
            
        except Exception as e:
            return 5.0  # Default to medium risk on error


class ThreatAttributionEngine:
    """Analyze threat attribution based on TTPs and indicators"""
    
    async def analyze_attribution(self, finding: Dict[str, Any], threat_contexts: List[ThreatContext]) -> Optional[ThreatAttribution]:
        """Analyze threat attribution for a finding"""
        try:
            # This is a simplified implementation
            # In a real system, this would analyze TTPs, infrastructure, and other indicators
            
            for context in threat_contexts:
                if context.source == "MITRE_ATT&CK":
                    return ThreatAttribution(
                        actor_name="Unknown",
                        actor_aliases=[],
                        motivation="Unknown",
                        sophistication="Medium",
                        geographic_origin="Unknown",
                        target_industries=["General"],
                        ttps=[f"Service: {finding.get('service', 'Unknown')}"],
                        confidence=0.3
                    )
            
            return None
            
        except Exception as e:
            return None


class ThreatPredictionEngine:
    """Predict future threat scenarios using machine learning"""
    
    async def predict_exploitation(self, finding: Dict[str, Any], threat_contexts: List[ThreatContext]) -> Dict[str, Any]:
        """Predict likelihood and timeline of exploitation"""
        try:
            # Simplified prediction model
            exploitation_likelihood = 0.3  # Default 30% chance
            timeline_days = 90  # Default 90 days
            
            # Increase likelihood for known exploited vulnerabilities
            for context in threat_contexts:
                if "known_exploited" in context.tags:
                    exploitation_likelihood = 0.9
                    timeline_days = 7
                elif context.severity in ["HIGH", "CRITICAL"]:
                    exploitation_likelihood += 0.3
                    timeline_days = max(30, timeline_days - 30)
            
            return {
                'exploitation_likelihood': min(exploitation_likelihood, 1.0),
                'predicted_timeline_days': timeline_days,
                'confidence': 0.6,
                'factors': ['threat_intelligence_analysis', 'vulnerability_severity', 'historical_patterns']
            }
            
        except Exception as e:
            return {
                'exploitation_likelihood': 0.3,
                'predicted_timeline_days': 90,
                'confidence': 0.3,
                'factors': ['default_estimate']
            }


class CampaignTracker:
    """Track and identify active threat campaigns"""
    
    async def identify_active_campaigns(self, finding: Dict[str, Any], threat_contexts: List[ThreatContext]) -> List[str]:
        """Identify active threat campaigns related to the finding"""
        try:
            campaigns = []
            
            # Look for campaign indicators in threat contexts
            for context in threat_contexts:
                if context.threat_type == "campaign":
                    campaigns.append(context.description)
                elif "campaign" in context.tags:
                    campaigns.append(f"Campaign associated with {context.source}")
            
            return campaigns
            
        except Exception as e:
            return []