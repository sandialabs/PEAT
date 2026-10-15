"""
PEAT-specific stand-ins for helpers that the vendored Beremiz code imports
from Beremiz's ``util`` package, which is not vendored.
"""


def NoTranslate(x):
    """Equivalent of ``util.TranslationCatalogs.NoTranslate``."""
    return x
