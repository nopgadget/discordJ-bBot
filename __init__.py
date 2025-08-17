"""
CyberCorps SFS Job Scanner

A Python-based tool that automatically scans job postings to identify positions 
eligible for CyberCorps Scholarship for Service (SFS) funding.
"""

__version__ = "1.0.0"
__author__ = "CyberCorps SFS Job Scanner"
__description__ = "Identify CyberCorps SFS eligible positions with advanced keyword analysis"

from .scanner import JobKeywordScanner
from .database import JobDatabase
from .progress_bar import ProgressBar

__all__ = ['JobKeywordScanner', 'JobDatabase', 'ProgressBar']
