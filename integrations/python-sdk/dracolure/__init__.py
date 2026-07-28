"""DracoLure Python SDK — client + injectable middleware.

    from dracolure import DracoLureClient, DracoLureMiddleware
"""

from .client import DracoLureClient, DracoLureError, Verdict
from .middleware import DracoLureMiddleware

__version__ = "1.0.0"
__all__ = [
    "DracoLureClient",
    "DracoLureError",
    "Verdict",
    "DracoLureMiddleware",
    "__version__",
]
