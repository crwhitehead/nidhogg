"""
Detection rules for Nidhogg.

This package provides a framework for defining and evaluating detection
rules for various types of suspicious behavior.
"""

from nidhogg.rules.finding import Finding, Severity, AnalysisResults
from nidhogg.rules.rule_engine import RuleEngine, Rule, RuleCategory