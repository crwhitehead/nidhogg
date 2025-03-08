"""
Configuration handling for Nidhogg.

This module provides configuration management for the analysis framework.
"""

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Set

from nidhogg.core.utils import get_package_root


@dataclass
class AnalysisConfig:
    """Configuration settings for a bytecode analysis run."""
    
    # General settings
    target_file: str = ""
    function_to_run: Optional[str] = None
    function_args: List[str] = field(default_factory=list)
    verbose: bool = False
    
    # Analysis options
    trace_imports: bool = True
    trace_stdlib: bool = False
    sandbox_execution: bool = True
    max_execution_time: int = 60  # seconds
    
    # Detection options
    sensitivity: str = "medium"  # "low", "medium", "high"
    report_format: str = "console"  # "console", "json", "html"
    output_file: Optional[str] = None
    
    # Analysis customization
    enabled_analyzers: List[str] = field(
        default_factory=lambda: ["opcode", "call", "import", "behavioral"]
    )
    enabled_rules: List[str] = field(
        default_factory=lambda: ["all"]
    )


def load_config(config_file: str) -> AnalysisConfig:
    """
    Load configuration from a JSON file.
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        Loaded configuration object
        
    Raises:
        FileNotFoundError: If the configuration file is not found
        json.JSONDecodeError: If the configuration file is invalid JSON
    """
    with open(config_file, 'r') as f:
        config_data = json.load(f)
    
    # Create config with defaults and override with file values
    config = AnalysisConfig()
    
    # Update config with values from file
    for key, value in config_data.items():
        if hasattr(config, key):
            setattr(config, key, value)
    
    return config


def save_config(config: AnalysisConfig, config_file: str) -> None:
    """
    Save configuration to a JSON file.
    
    Args:
        config: Configuration object to save
        config_file: Path to the configuration file
    """
    with open(config_file, 'w') as f:
        json.dump(asdict(config), f, indent=2)


def get_default_config_path() -> str:
    """
    Get the path to the default configuration file.
    
    Returns:
        Path to the default configuration file
    """
    return os.path.join(get_package_root(), 'config', 'default_config.json')