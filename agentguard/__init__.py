"""AgentGuard: pre-signing risk engine for AI-agent payments (research prototype)."""
from .engine import ENGINE_VERSION, evaluate

__all__ = ["evaluate", "ENGINE_VERSION"]
