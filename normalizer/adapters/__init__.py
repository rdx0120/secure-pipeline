from .base import Adapter, EmptyDocumentError, ScanRun
from .bandit import BanditAdapter
from .gitleaks import GitleaksAdapter
from .semgrep import SemgrepAdapter
from .trivy import TrivyAdapter

ADAPTERS = {
    a.tool: a
    for a in (BanditAdapter(), GitleaksAdapter(), SemgrepAdapter(), TrivyAdapter())
}

__all__ = ["Adapter", "ScanRun", "EmptyDocumentError", "ADAPTERS",
           "BanditAdapter", "GitleaksAdapter", "SemgrepAdapter", "TrivyAdapter"]
