"""Operational errors with deliberately sanitized messages."""


class DetectionError(Exception):
    """Assessment failed; neither safety nor vulnerability has been established."""
