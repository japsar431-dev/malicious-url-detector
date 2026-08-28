from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Payload for submitting a URL to scan."""
    url: str = Field(..., min_length=1, max_length=4096, description="The URL to analyze")


class ExtractedFeatures(BaseModel):
    """Extracted structural and heuristic features of the URL."""
    url_length: int
    hostname_length: int
    dot_count: int
    hyphen_count: int
    underscore_count: int
    slash_count: int
    question_mark_count: int
    equal_count: int
    at_symbol_count: int
    special_char_count: int
    digit_count: int
    digit_ratio: float
    is_ip_address: bool
    is_https: bool
    tld: str
    is_suspicious_tld: bool
    entropy: float
    suspicious_keywords: List[str]
    subdomain_count: int
    has_at_symbol: bool
    has_double_slash_redirect: bool
    has_punycode: bool
    has_port: bool
    port: Optional[int] = None
    is_shortened_url: bool


class ScanResponse(BaseModel):
    """Result of a URL threat scan."""
    id: Optional[int] = None
    url: str
    domain: str
    risk_score: int = Field(..., ge=0, le=100)
    classification: str = Field(..., description="SAFE | SUSPICIOUS | MALICIOUS")
    detection_reasons: List[str]
    extracted_features: Dict[str, Any]
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class HistoryResponse(BaseModel):
    """List of historical scans."""
    total: int
    scans: List[ScanResponse]


class AnalyticsResponse(BaseModel):
    """Aggregate statistics across all URL scans."""
    total_scans: int
    safe_scans: int
    suspicious_scans: int
    malicious_scans: int
    average_risk_score: int
    unique_domains: int
    safe_percentage: float
    suspicious_percentage: float
    malicious_percentage: float
    top_suspicious_tlds: Optional[List[Dict[str, Any]]] = None
    recent_scans: Optional[List[ScanResponse]] = None


class DBHealthResponse(BaseModel):
    """Database health check response."""
    status: str
    connected: bool
    database: str
    host: str
    port: int
    user: str
    table_exists: bool
    message: str
