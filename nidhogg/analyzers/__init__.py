"""
Analyzer modules for Nidhogg.

This package contains various analyzers that process bytecode execution 
events to detect suspicious or malicious patterns.
"""

from nidhogg.analyzers.base_analyzer import BaseAnalyzer
from nidhogg.analyzers.opcode_analyzer import OpcodeAnalyzer
from nidhogg.analyzers.call_analyzer import CallAnalyzer
from nidhogg.analyzers.import_analyzer import ImportAnalyzer
from nidhogg.analyzers.behavioral_analyzer import BehavioralAnalyzer

# Factory function to create analyzers
def create_analyzer(analyzer_type: str, **kwargs) -> BaseAnalyzer:
    """
    Create an analyzer of the specified type.
    
    Args:
        analyzer_type: Type of analyzer to create (opcode, call, import, behavioral)
        **kwargs: Arguments to pass to the analyzer constructor
        
    Returns:
        A new analyzer instance
        
    Raises:
        ValueError: If the analyzer type is unknown
    """
    analyzers = {
        'opcode': OpcodeAnalyzer,
        'call': CallAnalyzer,
        'import': ImportAnalyzer,
        'behavioral': BehavioralAnalyzer,
    }
    
    if analyzer_type not in analyzers:
        raise ValueError(f"Unknown analyzer type: {analyzer_type}")
    
    return analyzers[analyzer_type](**kwargs)