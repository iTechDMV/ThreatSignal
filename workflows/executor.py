import asyncio
from typing import Dict, Any
from .playbooks import PlaybookLoader
from .models import PlaybookStep


class PlaybookExecutor:
    def __init__(self, integrations: Dict[str, Any]):
        """
        integrations = {
            "edr": CrowdStrikeConnector(...),
            "firewall": FirewallConnector(...),
            "intel": VirusTotalConnector(...),
        }
        """
        self.integrations = integrations
        self.loader = PlaybookLoader()

    async def run(self, playbook_name: str, context: Dict[str, Any]):
        playbook = self.loader.load(playbook_name)
        steps = self.loader.resolve_order(playbook)

        results = []

        for step in steps:
            if step.approval:
                # In v3: Slack/PagerDuty approval workflow
                print(f"Awaiting approval from {step.approval} for step {step.id}")

            step_result = await self._execute_step(step, context)
            results.append(step_result)

        return results

    async def _execute_step(self, step: PlaybookStep, context: Dict[str, Any]):
        step_output = {"step": step.id, "actions": []}

        for action in step.automated_actions:
            action_name = action["action"]
            target = context.get(action["target"])
            params = action.get("params", {})

            integration_name, method_name = action_name.split(".")
            integration = self.integrations[integration_name]
            method = getattr(integration, method_name)

            if isinstance(target, list):
                tasks = [method(t, **params) for t in target]
                result = await asyncio.gather(*tasks)
            else:
                result = await method(target, **params)

            step_output["actions"].append({
                "action": action_name,
                "target": target,
                "result": result,
            })

        return step_output
