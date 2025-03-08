"""
Rule engine for Nidhogg.

This module provides the framework for defining, loading, and evaluating
detection rules for suspicious behavior patterns.
"""

import enum
import json
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple, Union

from nidhogg.core.utils import get_package_root
from nidhogg.rules.finding import Finding, Severity


class RuleCategory(enum.Enum):
    """Categories of detection rules."""
    OPCODE = "opcode"             # Suspicious opcode patterns
    FUNCTION_CALL = "function"    # Suspicious function calls
    IMPORT = "import"             # Suspicious imports
    BEHAVIOR = "behavior"         # Suspicious behavioral patterns
    OBFUSCATION = "obfuscation"   # Code obfuscation techniques
    NETWORK = "network"           # Network-related activities
    FILE = "file"                 # File-related activities
    PERSISTENCE = "persistence"   # Persistence mechanisms
    EVASION = "evasion"           # Evasion techniques


@dataclass
class Rule:
    """
    A detection rule for identifying suspicious behavior.
    
    Each rule defines a pattern to match and information about
    the detected behavior.
    """
    id: str
    name: str
    description: str
    category: RuleCategory
    severity: Severity
    detection: Dict[str, Any]
    reference: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the rule to a dictionary.
        
        Returns:
            Dictionary representation of the rule
        """
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category.value,
            'severity': self.severity.value,
            'detection': self.detection,
            'reference': self.reference
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Rule':
        """
        Create a rule from a dictionary.
        
        Args:
            data: Dictionary representation of a rule
            
        Returns:
            New Rule instance
        """
        # Convert string enum values to enum members
        category = RuleCategory(data['category'])
        severity = Severity(data['severity'])
        
        return Rule(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            category=category,
            severity=severity,
            detection=data['detection'],
            reference=data.get('reference')
        )


class RuleEngine:
    """
    Engine for loading and applying detection rules.
    """
    
    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize the rule engine.
        
        Args:
            rules_dir: Directory containing rule files (optional)
        """
        self.rules: Dict[str, Rule] = {}
        
        # Default to rules directory in package
        if rules_dir is None:
            rules_dir = os.path.join(get_package_root(), 'rules', 'definitions')
        
        self.rules_dir = rules_dir
    
    def load_rules(self, categories: Optional[List[RuleCategory]] = None) -> None:
        """
        Load rules from the rules directory.
        
        Args:
            categories: Optional list of categories to load (loads all if None)
        """
        self.rules.clear()
        
        # Walk through the rules directory
        for dirpath, dirnames, filenames in os.walk(self.rules_dir):
            for filename in filenames:
                if filename.endswith('.json'):
                    file_path = os.path.join(dirpath, filename)
                    try:
                        with open(file_path, 'r') as f:
                            rule_data = json.load(f)
                            
                            # Handle single rule or list of rules
                            if isinstance(rule_data, dict):
                                self._add_rule_if_category_matches(rule_data, categories)
                            elif isinstance(rule_data, list):
                                for rule_item in rule_data:
                                    self._add_rule_if_category_matches(rule_item, categories)
                    except json.JSONDecodeError:
                        # Skip invalid JSON files
                        continue
    
    def _add_rule_if_category_matches(self, 
                                     rule_data: Dict[str, Any],
                                     categories: Optional[List[RuleCategory]]) -> None:
        """
        Add a rule if its category matches the filter.
        
        Args:
            rule_data: Rule data dictionary
            categories: Optional category filter
        """
        # Check if category matches filter
        rule_category = RuleCategory(rule_data['category'])
        if categories is None or rule_category in categories:
            rule = Rule.from_dict(rule_data)
            self.rules[rule.id] = rule
    
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """
        Get a rule by ID.
        
        Args:
            rule_id: Rule ID to retrieve
            
        Returns:
            Rule if found, None otherwise
        """
        return self.rules.get(rule_id)
    
    def get_rules_by_category(self, category: RuleCategory) -> List[Rule]:
        """
        Get all rules in a category.
        
        Args:
            category: Category to retrieve
            
        Returns:
            List of rules in the category
        """
        return [rule for rule in self.rules.values() if rule.category == category]