import yaml
from pathlib import Path
from .models import Playbook, PlaybookStep


class PlaybookLoader:
    def __init__(self, directory: str = "playbooks"):
        self.directory = Path(directory)

    def load(self, name: str) -> Playbook:
        path = self.directory / f"{name}.yml"
        if not path.exists():
            raise FileNotFoundError(f"Playbook not found: {path}")

        data = yaml.safe_load(path.read_text())
        steps = [
            PlaybookStep(
                id=s["id"],
                phase=s["phase"],
                automated_actions=s.get("automated_actions", []),
                approval=s.get("approval"),
                dependencies=s.get("dependencies", []),
            )
            for s in data.get("steps", [])
        ]

        return Playbook(name=data["name"], steps=steps)

    @staticmethod
    def resolve_order(playbook: Playbook) -> List[PlaybookStep]:
        ordered = []
        remaining = {s.id: s for s in playbook.steps}

        while remaining:
            ready = [
                s for s in remaining.values()
                if all(dep not in remaining for dep in s.dependencies)
            ]
            if not ready:
                raise RuntimeError("Circular dependency detected in playbook")

            for step in ready:
                ordered.append(step)
                del remaining[step.id]

        return ordered
