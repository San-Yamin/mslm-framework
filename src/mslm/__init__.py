"""Mini-App Security Layer Model research implementation."""

from .risk import CCRSResult, Severity, calculate_ccrs

__all__ = ["CCRSResult", "Severity", "calculate_ccrs"]
__version__ = "0.2.0"

