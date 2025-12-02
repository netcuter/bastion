"""
Machine Learning module for security analysis
100% OFFLINE - no external API calls
"""

from .fp_classifier import FalsePositiveClassifier
from .training_data import TrainingDataGenerator

__all__ = [
    'FalsePositiveClassifier',
    'TrainingDataGenerator'
]
