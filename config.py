"""Configuration management for Injecticide."""

import json
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class TestConfig:
    """Configuration for a test suite run."""
    
    # Target configuration
    target_service: str = "anthropic"
    api_key: Optional[str] = None
    model: Optional[str] = None
    endpoint_url: Optional[str] = None
    
    # Test selection
    payload_categories: List[str] = field(default_factory=lambda: ["baseline"])
    custom_payloads: List[str] = field(default_factory=list)
    
    # Rate limiting
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    delay_between_requests: float = 0
    
    # Output configuration
    output_format: str = "json"  # json, csv, html
    output_file: Optional[str] = None
    verbose: bool = False
    
    # Safety settings
    max_requests: int = 100
    timeout: int = 30
    stop_on_detection: bool = False
    
    @classmethod
    def from_file(cls, path: str) -> "TestConfig":
        """Load configuration from YAML or JSON file."""
        path_obj = Path(path)
        
        if not path_obj.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        
        with open(path_obj, 'r') as f:
            if path_obj.suffix in ['.yaml', '.yml']:
                data = yaml.safe_load(f)
            elif path_obj.suffix == '.json':
                data = json.load(f)
            else:
                raise ValueError(f"Unsupported config format: {path_obj.suffix}")
        
        return cls(**data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "target_service": self.target_service,
            "model": self.model,
            "payload_categories": self.payload_categories,
            "requests_per_minute": self.requests_per_minute,
            "output_format": self.output_format,
            "max_requests": self.max_requests,
        }
