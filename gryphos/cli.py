"""Interactive terminal experience for Gryphos.

Built-in commands take precedence; ordinary conversational text is routed to
the agent. Unknown single-word typos get suggestions. Ctrl+C cancels the
current input or operation without killing the session; `exit` quits cleanly.
"""

from __future__ import annotations

import difflib
import logging
from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .agent import run_agent
from .config import ConfigError, Settings, get_settings
from .ctf import ChallengeError, discover_challenges, load_challenge, run_solver
from .ctf.report import generate_ctf_report
from .llm import GryphosLLM, LLMError
from .logging_setup import setup_logging
from .reporting import generate_reports
from .scope import EXPAND_SCOPE_CONFIRMATION, ScopeError, ScopeManager, validate_target
from .session import Session, SessionStore, new_session_id
from .tools import build_registry

log = logging.getLogger("gryphos.cli")

COMMANDS = (
    "help", "models", "model", "scope", "assess", "solve", "clear", "status",
    "sessions", "inspect", "history", "report", "config", "tools", "exit",
)

BANNER = """[bold green]═══ GRYPHOS ═══[/bold green]
Approval-based AI security assessment assistant.
Every network-active action requires your explicit approval.
Type [bold]help[/bold] for commands, [bold]exit[/bold] to quit."""


@dataclass
class AppState:
    settings: Settings
    llm: GryphosLLM
    registry: dict
    store: SessionStore
    console: Console
    scope: ScopeManager | None = None
    history: list[dict] = field(default_factory=list)  # REPL transcript
    last_session: Session | None = None
    last_target: str | None = None

    def __post_init__(self) -> None:
        if self.scope is None:
            self.scope = ScopeManager(baseline=tuple(self.settings.allowed_targets))


def _fmt_models(models, console: Console, limit: int = 60) -> None:
    table = Table(title=f"OpenRouter models ({len(models)} total)", show_lines=False)
    table.add_column("Model ID", style="cyan")
    table.add_column("Name")
    table.add_column("Context", justify="right")
    table.add_column("Free", justify="center")
    for m in models[:limit]:
        table.add_row(
            m.id, m.name,
            str(m.context_length) if m.context_length else "?",
            "yes" if m.is_free else "",
        )
    console.print(table)
    if len(models) > limit:
        console.print(
            f"[dim]Showing {limit} of {len(models)}. Model listing is not a "
            "guarantee of availability or free pricing — select any exact ID with "
            "`model <id>`.[/dim]"
        )


def _suggest(word: str) -> str | None:
    matches = difflib.get_close_matches(word.lower(), COMMANDS, n=1, cutoff=0.7)
    return matches[0] if matches else None


def handle_line(state: AppState, line: str) -> bool:
    """Handle one REPL line. Returns False to exit the loop.

    Built-in commands take precedence over natural-language routing.
    """
    text = line.strip()
    if not text:
        return True
    state.history.append({"role": "user", "content": text})

    lowered = text.lower()
    parts = text.split(maxsplit=1)
    command = parts[0].lower()
    argument = parts[1].strip() if len(parts) > 1 else ""

    try:
        if lowered in {"exit", "quit"}:
            return False

        if command == "help":
            _cmd_help(state)
        elif command == "models":
            _cmd_models(state)
        elif command == "model":
            _cmd_model(state, argument)
        elif command == "scope":
            _cmd_scope(state, argument)
        elif command == "assess":
            _cmd_assess(state, argument)
        elif command == "solve":
            _cmd_solve(state, argument)
        elif command == "clear":
            _cmd_clear(state)
        elif command == "status":
            _cmd_status(state)
        elif command == "sessions":
            _cmd_sessions(state)
        elif command == "inspect":
            _cmd_inspect(state, argument)
        elif command == "history":
            _cmd_history(state)
        elif command == "report":
            _cmd_report(state, argument)
        elif command == "config":
            _cmd_config(state)
        elif command == "tools":
            _cmd_tools(state)
        else:
            _route_unknown(state, text, command)
    except ConfigError as exc:
        state.console.print(f"[red]Configuration problem:[/red] {exc}")
    except LLMError as exc:
        state.console.print(f"[red]AI error:[/red] {exc}")
    except KeyboardInterrupt:
        state.console.print("\n[yellow]Interrupted. Type 'exit' to quit.[/yellow]")
    except EOFError:
        return False
    except Exception as exc:  # keep the REPL alive on unexpected errors
        log.exception("Unhandled REPL error")
        state.console.print(f"[red]Unexpected error:[/red] {type(exc).__name__}: {exc}")
    return True


def _route_unknown(state: AppState, text: str, first_word: str) -> None:
    suggestion = _suggest(first_word)
    looks_like_command = len(text.split()) == 1 and suggestion
    if looks_like_command:
        state.console.print(
            f"[yellow]Unknown command {first_word!r}. Did you mean [bold]{suggestion}[/bold]? "
            "Type 'help' for the command list.[/yellow]"
        )
        return
    # Natural language: route to the agent.
    state.console.print("[dim]Routing to the Gryphos agent…[/dim]")
    _run_assessment(state, objective=text, target=state.last_target, interactive_target=False)


def _cmd_help(state: AppState) -> None:
    state.console.print(Panel(
        "[bold]Built-in commands[/bold]\n"
        "  help              Show this help\n"
        "  models            List OpenRouter models (ID + display name)\n"
        "  model <exact-id>  Select a model by exact OpenRouter ID\n"
        "  scope             Show the authorized scope (see also: scope set|narrow|reset)\n"
        "  assess [text]     Run an assessment (optionally with an objective)\n"
        "  solve [id]        Solve a configured CTF challenge (list challenges if no id)\n"
        "  status            Current model, scope, and session info\n"
        "  sessions          List saved sessions\n"
        "  inspect <id>       Inspect a saved session (read-only, never replays)\n"
        "  history           Show this session's input history\n"
        "  report [id]       Show/regenerate report for a session\n"
        "  config            Show configuration (secrets redacted)\n"
        "  tools             List registered security tools\n"
        "  clear             Clear the screen (sessions/reports are kept)\n"
        "  exit              Quit cleanly\n\n"
        "[bold]Natural language[/bold]\n"
        "  Anything else is sent to the AI agent, e.g.\n"
        "  \"Explain the last scan\" or \"Check my local web server's HTTP headers\".\n"
        "  Active checks still require your approval.",
        title="Gryphos help",
        border_style="cyan",
    ))


def _cmd_models(state: AppState) -> None:
    try:
        models = state.llm.list_models(force_refresh=True)
    except LLMError as exc:
        state.console.print(f"[red]Could not fetch model list:[/red] {exc}")
        return
    _fmt_models(models, state.console)


def _cmd_model(state: AppState, argument: str) -> None:
    if not argument:
        state.console.print(
            f"Current model: [cyan]{state.llm.model}[/cyan]\n"
            "Use [bold]model <exact-id>[/bold], e.g. [bold]model cohere/command-a[/bold]."
        )
        return
    changed, message = state.llm.set_model(argument)
    style = "green" if changed else "yellow"
    state.console.print(f"[{style}]{message}[/{style}]")


def _show_scope(state: AppState) -> None:
    scope = state.scope
    baseline = ", ".join(scope.baseline)
    state.console.print(f"Authorized scope (baseline): [cyan]{baseline}[/cyan]")
    if tuple(scope.effective) != tuple(scope.baseline):
        state.console.print(
            f"Effective scope (narrowed): [cyan]{', '.join(scope.effective)}[/cyan]"
        )
    state.console.print(
        "[dim]Only literal IPs inside this scope can be assessed. Narrowing is free; "
        "widening beyond the baseline requires the explicit confirmation token. "
        "The model can never change scope.[/dim]\n"
        "[dim]Usage: scope | scope narrow <ip[,ip...]> | scope set <ip[,ip...]> | scope reset[/dim]"
    )
    if scope.changes:
        last = scope.changes[-1]
        state.console.print(
            f"[dim]Last change: {last['kind']} ({last['authorization']}) at {last['at']}[/dim]"
        )


def _cmd_scope(state: AppState, argument: str) -> None:
    tokens = argument.split(maxsplit=1)
    sub = tokens[0].lower() if tokens else ""
    rest = tokens[1].strip() if len(tokens) > 1 else ""

    if not sub:
        _show_scope(state)
        return

    if sub == "reset":
        record = state.scope.reset()
        state.console.print(
            f"[green]Scope reset to baseline:[/green] {', '.join(state.scope.effective)}"
        )
        state.console.print(f"[dim]Change recorded: {record['kind']} ({record['authorization']}).[/dim]")
        return

    if sub not in {"set", "add", "narrow"}:
        state.console.print(
            "[yellow]Usage: scope | scope narrow <ip[,ip...]> | scope set <ip[,ip...]> | scope reset[/yellow]"
        )
        return

    if not rest:
        state.console.print("[yellow]Provide one or more IPs/CIDRs, comma-separated.[/yellow]")
        return

    candidate = tuple(part.strip() for part in rest.split(",") if part.strip())
    try:
        kind = state.scope.classify(candidate)
    except ScopeError as exc:
        state.console.print(f"[red]Invalid scope:[/red] {exc}")
        return

    confirmation = ""
    if kind == "expand":
        state.console.print(Panel(
            "[bold red]This expands the authorized scope beyond the configured baseline.[/bold red]\n\n"
            f"[bold]Baseline:[/bold] {', '.join(state.scope.baseline)}\n"
            f"[bold]Proposed:[/bold] {', '.join(candidate)}\n\n"
            "Expanding scope authorizes new destinations. This is your explicit, "
            "out-of-band decision — the model cannot do this. Leave blank to abort.",
            title="Confirm scope expansion",
            border_style="red",
        ))
        try:
            typed = state.console.input(
                f"Type [bold]{EXPAND_SCOPE_CONFIRMATION}[/bold] to confirm: "
            ).strip()
        except (KeyboardInterrupt, EOFError):
            state.console.print("[yellow]Scope expansion aborted.[/yellow]")
            return
        if typed != EXPAND_SCOPE_CONFIRMATION:
            state.console.print("[yellow]Scope expansion aborted (confirmation not given).[/yellow]")
            return
        confirmation = typed

    try:
        record = state.scope.change(candidate, confirmation=confirmation)
    except ScopeError as exc:
        state.console.print(f"[red]Scope change rejected:[/red] {exc}")
        return
    state.console.print(
        f"[green]Scope {record['kind']}:[/green] {', '.join(state.scope.effective)}"
    )
    state.console.print(f"[dim]Authorization: {record['authorization']}.[/dim]")


def _cmd_status(state: AppState) -> None:
    last = state.last_session
    table = Table(title="Gryphos status", show_header=False)
    table.add_column("Key", style="cyan")
    table.add_column("Value")
    table.add_row("Model", state.llm.model)
    table.add_row("Scope", ", ".join(state.scope.baseline))
    if tuple(state.scope.effective) != tuple(state.scope.baseline):
        table.add_row("Effective scope", ", ".join(state.scope.effective))
    table.add_row("Last target", state.last_target or "(none)")
    table.add_row("Step limit", str(state.settings.max_agent_steps))
    table.add_row("Time budget", f"{state.settings.time_budget_seconds}s")
    table.add_row("Max approval level", f"L{state.settings.max_approval_level}")
    table.add_row("Tools", ", ".join(sorted(state.registry)))
    table.add_row("Last session", last.session_id if last else "(none)")
    table.add_row("Saved sessions", str(len(state.store.list_sessions())))
    state.console.print(table)


def _cmd_sessions(state: AppState) -> None:
    entries = state.store.list_sessions()
    if not entries:
        state.console.print("[yellow]No saved sessions yet.[/yellow]")
        return
    table = Table(title=f"Saved sessions ({len(entries)})")
    table.add_column("Session ID", style="cyan")
    table.add_column("Created")
    table.add_column("Objective")
    table.add_column("Target")
    for e in entries[:30]:
        table.add_row(
            str(e.get("session_id", "?")),
            str(e.get("created_at", "?"))[:25],
            str(e.get("objective", "?"))[:48],
            str(e.get("target") or "-"),
        )
    state.console.print(table)
    state.console.print("[dim]Inspect one with: inspect <session-id> (read-only).[/dim]")


def _cmd_inspect(state: AppState, argument: str) -> None:
    session_id = argument.strip()
    if not session_id:
        state.console.print("[yellow]Usage: inspect <session-id>. See 'sessions' for IDs.[/yellow]")
        return
    try:
        session = state.store.load(session_id)
    except (FileNotFoundError, ValueError) as exc:
        state.console.print(f"[red]{exc}[/red]")
        return
    state.console.print(Panel(
        "[bold]Inspection is read-only.[/bold] Nothing from this session is "
        "replayed and no historical approval is treated as current authorization. "
        "Use [bold]report <id>[/bold] to regenerate the full report from this "
        "session record.",
        title="Gryphos session inspection",
        border_style="cyan",
    ))
    table = Table(title=f"Session {session.session_id}", show_header=False)
    table.add_column("Key", style="cyan")
    table.add_column("Value")
    table.add_row("Created", session.created_at)
    table.add_row("Completed", session.completed_at or "(in progress)")
    table.add_row("Model", session.model)
    table.add_row("Objective", session.objective)
    table.add_row("Target", session.target or "(none)")
    table.add_row("Scope", ", ".join(session.scope_snapshot) or "(none)")
    table.add_row("History entries", str(len(session.history)))
    table.add_row("Proposals", str(len(session.proposals)))
    table.add_row("Approval decisions", str(len(session.approvals)))
    table.add_row("Tool executions", str(len(session.tool_runs)))
    table.add_row("Findings", str(len(session.findings)))
    table.add_row("Errors", str(len(session.errors)))
    table.add_row("Warnings", str(len(session.warnings)))
    table.add_row("JSON evidence", session.report_json or "(not generated)")
    table.add_row("Markdown report", session.report_markdown or "(not generated)")
    state.console.print(table)

    if session.findings:
        state.console.print("[bold]Findings:[/bold]")
        for f in session.findings[-10:]:
            sev = f.get("severity", "?")
            state.console.print(f"  [yellow]{sev}[/yellow] {f.get('title', '(untitled)')}")
    if session.approvals:
        state.console.print("[bold]Approval decisions:[/bold]")
        for a in session.approvals[-10:]:
            mark = str(a.get("decision", "?")).upper()
            state.console.print(
                f"  [cyan]{mark}[/cyan] {a.get('tool', '?')} on {a.get('target', '?')}"
            )
    if session.errors:
        state.console.print("[bold]Errors:[/bold]")
        for err in session.errors[-10:]:
            state.console.print(f"  [red]{err.get('source', '?')}:[/red] {err.get('message', '')}")


def _cmd_history(state: AppState) -> None:
    if not state.history:
        state.console.print("[dim]No input history yet.[/dim]")
        return
    for item in state.history[-30:]:
        role = item.get("role", "user")
        content = str(item.get("content", ""))[:120]
        state.console.print(f"[bold]{role}:[/bold] {content}")


def _cmd_report(state: AppState, argument: str) -> None:
    if argument:
        try:
            session = state.store.load(argument)
        except (FileNotFoundError, ValueError) as exc:
            state.console.print(f"[red]{exc}[/red]")
            return
        json_path, md_path = generate_reports(session, state.settings.reports_dir)
        state.console.print(f"[green]Report regenerated:[/green] {md_path}")
        state.console.print(f"[dim]JSON evidence: {json_path}[/dim]")
        return
    if state.last_session is None:
        entries = [e for e in state.store.list_sessions() if not e.get("corrupt")]
        if not entries:
            state.console.print("[yellow]No sessions available. Run an assessment first.[/yellow]")
            return
        session = state.store.load(entries[0]["session_id"])
    else:
        session = state.last_session
    json_path, md_path = generate_reports(session, state.settings.reports_dir)
    state.console.print(f"[green]Report saved:[/green] {md_path}")
    state.console.print(f"[dim]JSON evidence: {json_path}[/dim]")


def _cmd_config(state: AppState) -> None:
    import json as _json
    state.console.print(_json.dumps(state.settings.safe_summary(), indent=2))


def _cmd_tools(state: AppState) -> None:
    table = Table(title="Registered tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Level", justify="center")
    table.add_column("Network", justify="center")
    table.add_column("Risk")
    table.add_column("Approval")
    table.add_column("Description")
    for spec in state.registry.values():
        table.add_row(
            spec.name,
            f"L{spec.approval_level}",
            "yes" if spec.network_active else "no",
            spec.risk,
            spec.approval_policy,
            spec.description[:70] + ("…" if len(spec.description) > 70 else ""),
        )
    state.console.print(table)
    state.console.print(
        "[dim]Only these tools can ever execute. Levels 2+ require your explicit approval; "
        "Level 4 is disabled by default. The model cannot invent commands or tools.[/dim]"
    )


def _cmd_clear(state: AppState) -> None:
    state.console.print("\033[2J\033[H", end="")


def _cmd_assess(state: AppState, argument: str) -> None:
    objective = argument
    if not objective:
        objective = state.console.input("[bold]Assessment objective[/bold]: ").strip()
    if not objective:
        state.console.print("[yellow]No objective given; assessment cancelled.[/yellow]")
        return
    target = None
    if state.last_target:
        use_last = state.console.input(
            f"Target [default {state.last_target}, Enter to accept, or type an IP]: "
        ).strip()
        target = use_last or state.last_target
    else:
        target = state.console.input(
            "Target IP (must be in configured scope, Enter to let the AI ask): "
        ).strip() or None
    _run_assessment(state, objective=objective, target=target, interactive_target=True)


def _run_assessment(state: AppState, objective: str, target: str | None, interactive_target: bool) -> None:
    settings = state.settings
    if not settings.api_key_configured:
        raise ConfigError(
            "OPENROUTER_API_KEY is not configured. Copy .env.example to .env and set your key."
        )

    effective_scope = tuple(state.scope.effective)
    if target:
        try:
            target = validate_target(target, effective_scope)
            state.last_target = target
        except ScopeError as exc:
            state.console.print(f"[red]Target rejected:[/red] {exc}")
            return

    session = Session(
        session_id=new_session_id(),
        objective=objective,
        scope_snapshot=effective_scope,
        model=state.llm.model,
    )
    outcome = run_agent(
        state.llm, settings, objective, target,
        registry=state.registry, session=session, console=state.console,
        scope_items=effective_scope,
    )
    session.record_history("assistant", outcome.final_message or f"(status: {outcome.status})")
    session.complete()
    try:
        json_path, md_path = generate_reports(session, settings.reports_dir)
        state.console.print(f"[dim]Saved JSON evidence: {json_path}[/dim]")
        state.console.print(f"[dim]Saved Markdown report: {md_path}[/dim]")
    except OSError as exc:
        session.record_error("reporting", f"Could not write reports: {exc}")
        state.console.print(f"[red]Could not write reports:[/red] {exc}")
    try:
        state.store.save(session)
    except OSError as exc:
        state.console.print(f"[red]Could not save session:[/red] {exc}")
    state.last_session = session
    if target:
        state.last_target = target


def _cmd_solve(state: AppState, argument: str) -> None:
    settings = state.settings
    challenge_id = argument.strip()
    if not challenge_id:
        entries = discover_challenges(settings.ctf_challenges_dir)
        if not entries:
            state.console.print(
                f"[yellow]No challenges found in {settings.ctf_challenges_dir}. "
                "Add challenges/<id>/challenge.json.[/yellow]"
            )
            return
        table = Table(title=f"CTF challenges ({len(entries)})")
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Category")
        for e in entries:
            table.add_row(str(e.get("id", "?")), str(e.get("name", "?")), str(e.get("category", "?")))
        state.console.print(table)
        state.console.print("[dim]Solve one with: solve <id>[/dim]")
        return

    if not settings.api_key_configured:
        raise ConfigError(
            "OPENROUTER_API_KEY is not configured. Copy .env.example to .env and set your key."
        )
    try:
        challenge = load_challenge(settings.ctf_challenges_dir, challenge_id)
    except ChallengeError as exc:
        state.console.print(f"[red]Challenge error:[/red] {exc}")
        return

    session = Session(
        session_id=new_session_id(),
        objective=f"[ctf] {challenge.name}",
        scope_snapshot=(),
        model=state.llm.model,
        target=None,
    )

    def ask(question: str) -> str:
        return state.console.input(f"[cyan]Solver needs input:[/cyan] {question} ")

    outcome = run_solver(
        state.llm, settings, challenge,
        session=session, console=state.console, ask_user=ask,
    )
    session.record_history("assistant", outcome.message or f"(status: {outcome.status})")
    session.complete()
    try:
        json_path, md_path = generate_ctf_report(session, outcome.to_dict(), settings.reports_dir)
        state.console.print(f"[dim]Saved JSON evidence: {json_path}[/dim]")
        state.console.print(f"[dim]Saved Markdown report: {md_path}[/dim]")
    except OSError as exc:
        session.record_error("reporting", f"Could not write reports: {exc}")
        state.console.print(f"[red]Could not write reports:[/red] {exc}")
    try:
        state.store.save(session)
    except OSError as exc:
        state.console.print(f"[red]Could not save session:[/red] {exc}")
    state.last_session = session
    verdict = "SOLVED" if outcome.solved else "UNSOLVED"
    style = "green" if outcome.solved else "yellow"
    state.console.print(f"[{style}]{verdict}[/{style}] — {challenge.name} ({challenge.category})")


def run_repl(settings: Settings | None = None, console: Console | None = None) -> None:
    """Start the interactive Gryphos session."""
    settings = settings or get_settings()
    console = console or Console()
    setup_logging(settings.log_dir)

    if not settings.api_key_configured:
        console.print(
            "[red]OPENROUTER_API_KEY is not configured.[/red] "
            "Copy .env.example to .env and set your key from https://openrouter.ai/settings/keys."
        )
        raise SystemExit(1)

    llm = GryphosLLM(
        api_key=settings.api_key,
        model=settings.default_model,
        api_base=settings.api_base,
        request_timeout=settings.request_timeout,
        max_retries=settings.max_retries,
        catalog_ttl=settings.model_cache_ttl,
    )
    registry = build_registry(settings)
    store = SessionStore(settings.reports_dir)
    state = AppState(
        settings=settings, llm=llm, registry=registry,
        store=store, console=console,
    )

    console.print(Panel(BANNER, border_style="green"))
    console.print(
        f"Model: [cyan]{llm.model}[/cyan]   "
        f"Scope: [cyan]{', '.join(state.scope.baseline)}[/cyan]   "
        f"Max approval level: [cyan]L{settings.max_approval_level}[/cyan]"
    )

    while True:
        try:
            line = console.input("\n[bold green]gryphos[/bold green] ")
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Type 'exit' to quit.[/yellow]")
            continue
        except EOFError:
            break
        if not handle_line(state, line):
            break
    console.print("[dim]Goodbye. Sessions and reports are preserved in reports/.[/dim]")
