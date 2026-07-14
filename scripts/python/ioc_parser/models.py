from dataclasses import dataclass


@dataclass(slots=True)
class IOC:
    value: str
    ioc_type: str
    is_valid: bool