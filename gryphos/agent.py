"""Bounded agent loop.

Separates reasoning (LLM), validation (models/scope), authorization
(approval), tool execution (registry), and recording (session). Enforces:
step limit, total time budget, duplicate-call prevention, consecutive-failure
abort, registry-only dispatch, scope checks at execution time, and explicit
operator approval for every network-active action. Declining or cancelling
never executes anything.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from .approval import ApprovalManager, ApprovalRequest
from .llm import LLMError, build_system_prompt
from .models import (
    ClarificationDecision,
    ErrorDecision,
    FinalDecision,
    ToolCallDecision,
)
from .scope import ScopeError, validate_target
from .session import Session, utc_now_iso
from .tools import ToolError, ToolResult, ToolSpec, validate_args

log = logging.getLogger("gryphos.agent")

MAX_CONSECUTIVE_FAILURES = 3


@dataclass
class AgentOutcome:
    status: str  # "final" | "steps_exhausted" | "time_budget" | "failed" | "cancelled"
    final_message: str | None = None
    findings: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Agent:
    def __init__(
        self,
        llm,
        settings,
        registry: dict[str, ToolSpec],
        session: Session,
        console: Console | None = None,
        approve: Callable[[ApprovalRequest], bool] | None = None,
        ask_user: Callable[[str], str] | None = None,
    ):
        self.llm = llm
        self.settings = settings
        self.registry = registry
        self.session = session
        self.console = console or Console()
        self.approvals = ApprovalManager()
        self.system_prompt = build_system_prompt(registry)
        self._approve = approve or self._default_approve
        self._ask_user = ask_user or self._default_ask
        self.evidence: list[dict] = []
        self._fingerprints_seen: set[str] = set()
        self._failure_streak = 0

    # -- UI defaults ---------------------------------------------------------

    def _default_approve(self, request: ApprovalRequest) -> bool:
        traffic = (
            "[yellow]This sends network traffic to the target.[/yellow]"
            if request.network_active
            else "[dim]This tool sends no network traffic.[/dim]"
        )
        self.console.print(Panel(
            f"[bold]Tool:[/bold] {request.tool}\n"
            f"[bold]Target:[/bold] {request.target}\n"
            f"[bold]Purpose:[/bold] {request.purpose}\n"
            f"[bold]Reason from model:[/bold] {request.reason or '(none given)'}\n\n"
            f"[bold]Exact action:[/bold]\n{request.display}\n\n"
            f"[bold]Risk:[/bold] {request.risk}\n"
            f"[bold]Side effects:[/bold] {request.side_effects}\n"
            f"[bold]Timeout:[/bold] {request.timeout}s   "
            f"[bold]Output limit:[/bold] {request.output_limit} chars\n\n"
            f"{traffic}",
            title="Approval required",
            border_style="yellow",
        ))
        return Confirm.ask("Approve and run this action?", default=False)

    def _default_ask(self, question: str) -> str:
        return Prompt.ask(f"[cyan]Gryphos needs clarification:[/cyan] {question}")

    # -- main loop -----------------------------------------------------------

    def run(self, objective: str, target: str | None) -> AgentOutcome:
        try:
            safe_target = validate_target(target, self.settings.allowed_targets) if target else None
        except ScopeError as exc:
            self.console.print(f"[red]Target rejected:[/red] {exc}")
            self.session.record_error("scope", str(exc))
            return AgentOutcome(status="failed", final_message=str(exc), evidence=self.evidence)

        self.session.target = safe_target
        self.console.print(Panel(
            f"[bold]Objective:[/bold] {objective}\n"
            f"[bold]In-scope IP:[/bold] {safe_target or '(none — ask the model for a plan)'}\n"
            f"[bold]Model:[/bold] {self.llm.model}\n"
            f"[bold]Step limit:[/bold] {self.settings.max_agent_steps}   "
            f"[bold]Time budget:[/bold] {self.settings.time_budget_seconds}s",
            title="Gryphos assessment",
            border_style="cyan",
        ))

        deadline = time.monotonic() + self.settings.time_budget_seconds

        for step in range(1, self.settings.max_agent_steps + 1):
            if time.monotonic() > deadline:
                return self._stop("time_budget", "Time budget exhausted. Stopping safely.")
            try:
                decision = self.llm.decide(
                    objective=objective,
                    target=safe_target,
                    evidence=self.evidence,
                    step=step,
                    system_prompt=self.system_prompt,
                    history=self.session.history,
                )
            except LLMError as exc:
                log.error("LLM failure at step %s: %s", step, exc)
                self.session.record_error("llm", str(exc))
                self.console.print(f"[red]AI request failed:[/red] {exc}")
                return self._stop("failed", f"AI request failed: {exc}", errors=[str(exc)])

            if isinstance(decision, FinalDecision):
                return self._finalize(decision)

            if isinstance(decision, ErrorDecision):
                self.console.print(Panel(decision.message, title="Gryphos cannot proceed", border_style="red"))
                self.session.record_error("model", decision.message)
                return self._stop(
                    "failed",
                    f"The model could not proceed: {decision.message}",
                    errors=[decision.message],
                )

            if isinstance(decision, ClarificationDecision):
                self.session.proposals.append({"kind": "clarification", "question": decision.question, "step": step})
                self.console.print(f"[cyan]Clarification needed:[/cyan] {decision.question}")
                try:
                    answer = self._ask_user(decision.question)
                except (KeyboardInterrupt, EOFError):
                    return self._stop("cancelled", "Cancelled by operator during clarification.")
                if not answer or not answer.strip():
                    answer = "(no answer provided)"
                self.session.record_history("user", f"(clarification) {answer}")
                self.evidence.append({
                    "kind": "clarification",
                    "question": decision.question,
                    "answer": answer,
                    "step": step,
                })
                continue

            if not isinstance(decision, ToolCallDecision):
                continue
            outcome = self._handle_tool_call(decision, safe_target, step)
            if outcome is not None:
                return outcome
            if self._failure_streak >= MAX_CONSECUTIVE_FAILURES:
                return self._stop(
                    "failed",
                    f"Aborting after {self._failure_streak} consecutive rejected or failed "
                    "tool proposals. Review the evidence above.",
                )

        return self._stop(
            "steps_exhausted",
            "Maximum agent steps reached. Review the evidence above; no further tools will run.",
        )

    # -- tool handling -------------------------------------------------------

    def _handle_tool_call(
        self, decision: ToolCallDecision, safe_target: str | None, step: int
    ) -> AgentOutcome | None:
        tool_name = decision.tool
        proposal_record = {
            "kind": "tool_call",
            "tool": tool_name,
            "args": decision.args,
            "reason": decision.reason,
            "step": step,
            "at": utc_now_iso(),
        }
        self.session.proposals.append(proposal_record)

        spec = self.registry.get(tool_name)
        if spec is None:
            msg = f"Rejected unknown tool proposal: {tool_name!r}. Only registered tools can run."
            self.console.print(f"[red]{msg}[/red]")
            self.evidence.append({"kind": "rejected", "tool": tool_name, "reason": "Tool is not registered."})
            self.session.record_error("agent", msg)
            self._note_failure()
            return None

        try:
            args = validate_args(spec, decision.args)
        except ToolError as exc:
            self.console.print(f"[red]Rejected invalid arguments:[/red] {exc}")
            self.evidence.append({"kind": "rejected", "tool": tool_name, "reason": str(exc)})
            self._note_failure()
            return None

        # Scope enforcement for tools that act on a single target IP.
        if "target" in spec.input_schema.get("properties", {}):
            try:
                args["target"] = validate_target(str(args.get("target", "")), self.settings.allowed_targets)
            except ScopeError as exc:
                self.console.print(f"[red]Rejected out-of-scope proposal:[/red] {exc}")
                self.evidence.append({"kind": "rejected", "tool": tool_name, "reason": str(exc)})
                self._note_failure()
                return None
            if safe_target and args["target"] != safe_target:
                msg = "Proposed target differs from the target selected for this assessment."
                self.console.print(f"[red]Rejected:[/red] {msg}")
                self.evidence.append({"kind": "rejected", "tool": tool_name, "reason": msg})
                self._note_failure()
                return None

        display = self._display_for(spec, args)
        request = ApprovalRequest(
            tool=tool_name,
            target=str(args.get("target", "(none)")),
            args=dict(args),
            purpose=spec.purpose,
            display=display,
            network_active=spec.network_active,
            timeout=spec.timeout,
            output_limit=spec.max_output_chars,
            risk=spec.risk,
            side_effects=spec.side_effects,
            reason=decision.reason,
        )

        # Duplicate-call prevention: identical action already executed or refused.
        if request.fingerprint in self._fingerprints_seen:
            msg = "This exact action was already proposed in this session; not repeating it."
            self.console.print(f"[yellow]{msg} Asking the model to use existing evidence.[/yellow]")
            self.evidence.append({"kind": "note", "message": msg})
            return None

        if spec.network_active or spec.approval_policy == "explicit":
            try:
                approved = self._approve(request)
            except (KeyboardInterrupt, EOFError):
                self.session.approvals.append({**request.to_record(), "decision": "cancelled"})
                return self._stop("cancelled", "Cancelled by operator before execution.")
            self.approvals.record(request, approved=bool(approved))
            self.session.approvals.append({**request.to_record(), "decision": "approved" if approved else "declined"})
            if not approved:
                self._fingerprints_seen.add(request.fingerprint)
                self.console.print("[yellow]Declined. The model will be told the action was not authorized.[/yellow]")
                self.evidence.append({
                    "kind": "approval_refused",
                    "tool": tool_name,
                    "target": request.target,
                    "reason": "Operator declined the request.",
                })
                return None
            if not self.approvals.authorize(request):
                self.session.record_error("approval", "Approval state invalid; denying execution.")
                return self._stop("failed", "Approval state was invalid; nothing was executed.")
        else:
            # Passive tools: still recorded, no network consequence.
            self.session.approvals.append({**request.to_record(), "decision": "auto-passive"})

        self._fingerprints_seen.add(request.fingerprint)

        try:
            result = spec.execute(args, self.settings.allowed_targets, self.evidence)
        except (ToolError, ScopeError) as exc:
            self.console.print(f"[red]Tool rejected:[/red] {exc}")
            self.evidence.append({"kind": "tool_error", "tool": tool_name, "error": str(exc)})
            self.session.record_error("tool", str(exc))
            self._note_failure()
            return None
        except Exception as exc:  # unexpected internal failure — keep the loop safe
            log.exception("Tool %s crashed", tool_name)
            safe_msg = f"{type(exc).__name__}: {exc}"
            self.console.print(f"[red]Tool failed:[/red] {safe_msg}")
            self.evidence.append({"kind": "tool_error", "tool": tool_name, "error": safe_msg})
            self.session.record_error("tool", safe_msg)
            self._note_failure()
            return None

        self._record_result(result)
        return None

    def _note_failure(self) -> None:
        self._failure_streak += 1

    def _record_result(self, result: ToolResult) -> None:
        self._failure_streak = 0
        item = result.to_evidence()
        self.evidence.append(item)
        self.session.record_tool_run(item)
        style = "red" if result.error else "blue"
        self.console.print(Panel(
            result.output or "(No output)",
            title=f"{result.tool} result",
            border_style=style,
        ))

    def _display_for(self, spec: ToolSpec, args: dict) -> str:
        if spec.show is not None:
            return spec.show(args)
        return f"{spec.name}({args})"

    def _finalize(self, decision: FinalDecision) -> AgentOutcome:
        message = decision.message.strip()
        findings = [f.model_dump() for f in decision.findings]
        self.console.print(Panel(message, title="Gryphos analysis", border_style="green"))
        self.evidence.append({"kind": "final", "message": message, "findings": findings})
        self.session.findings.extend(findings)
        self.session.final_assessment = message
        return AgentOutcome(status="final", final_message=message, findings=findings, evidence=self.evidence)

    def _stop(self, status: str, message: str, errors: list[str] | None = None) -> AgentOutcome:
        border = {"cancelled": "yellow", "failed": "red"}.get(status, "yellow")
        self.console.print(Panel(message, title="Stopped", border_style=border))
        return AgentOutcome(
            status=status,
            final_message=message,
            evidence=self.evidence,
            errors=errors or [],
        )


def run_agent(
    llm,
    settings,
    objective: str,
    target: str | None,
    registry: dict[str, ToolSpec] | None = None,
    session: Session | None = None,
    console: Console | None = None,
    approve: Callable[[ApprovalRequest], bool] | None = None,
    ask_user: Callable[[str], str] | None = None,
) -> AgentOutcome:
    """Convenience wrapper used by the CLI and tests."""
    from .tools import build_registry

    if registry is None:
        registry = build_registry(settings)
    if session is None:
        from .session import new_session_id
        session = Session(
            session_id=new_session_id(),
            objective=objective,
            scope_snapshot=settings.allowed_targets,
            model=llm.model,
        )
    agent = Agent(
        llm, settings, registry, session,
        console=console, approve=approve, ask_user=ask_user,
    )
    session.record_history("user", objective)
    outcome = agent.run(objective, target)
    return outcome
