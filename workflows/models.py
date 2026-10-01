from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class PlaybookStep:
    id: str
    phase: str
    automated_actions: List[Dict]
    approval: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)


@dataclass
class Playbook:
    name: str
    steps: List[PlaybookStep]
