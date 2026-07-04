"""Codex runner exceptions. ``str(exc)`` is always generic/participant-safe;
operator-only context lives in ``.detail``, never in the message."""
from __future__ import annotations

from typing import Optional


class CodexRunnerError(Exception):
    def __init__(self, message: str, *, detail: Optional[str] = None):
        super().__init__(message)
        self.detail = detail


class RateLimitError(CodexRunnerError):
    def __init__(
        self,
        message: str = "생성 요청이 일시적으로 제한되었습니다. 잠시 후 다시 시도됩니다.",
        *,
        retry_after: float,
        detail: Optional[str] = None,
    ):
        super().__init__(message, detail=detail)
        self.retry_after = float(retry_after)


class GenerationTimeoutError(CodexRunnerError, TimeoutError):
    def __init__(
        self,
        message: str = "코드 생성 시간이 초과되었습니다.",
        *,
        detail: Optional[str] = None,
    ):
        super().__init__(message, detail=detail)


class GenerationError(CodexRunnerError):
    def __init__(
        self,
        message: str = "코드 생성에 실패했습니다.",
        *,
        detail: Optional[str] = None,
    ):
        super().__init__(message, detail=detail)
