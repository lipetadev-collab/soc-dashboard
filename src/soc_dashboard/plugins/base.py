from __future__ import annotations

from abc import ABC, abstractmethod

from soc_dashboard.models import SecurityEvent


class DetectionPlugin(ABC):
    @abstractmethod
    def process(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        raise NotImplementedError
