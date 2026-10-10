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
from .llm import GryphosLLM, LLMError
from .logging_setup import setup_logging
from .reporting import generate_reports
from .scope import ScopeError, validate_target
from .session import Session, SessionStore, new_session_id
from .tools import build_registry

log = logging.getLogger("gryphos.cli")

COMMANDS = (
    "help", "models", "model", "scope", "assess", "clear", "status",
    "sessions", "history", "report", "config", "tools", "exit",
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
    history: list[dict] = field(default_factory=list)  # REPL transcript
    last_session: Session | None = None
    last_target: str | None = None


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
            _cmd_scope(state)
        elif command == "assess":
            _cmd_assess(state, argument)
        elif command == "clear":
            _cmd_clear(state)
        elif command == "status":
            _cmd_status(state)
        elif command == "sessions":
            _cmd_sessions(state)
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
        "  scope             Show the authorized target scope\n"
        "  assess [text]     Run an assessment (optionally with an objective)\n"
        "  status            Current model, scope, and session info\n"
        "  sessions          List saved sessions\n"
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


def _cmd_scope(state: AppState) -> None:
    state.console.print(f"Authorized scope: [cyan]{', '.join(state.settings.allowed_targets)}[/cyan]")
    state.console.print(
        "[dim]Only literal IPs inside this scope can be assessed. "
        "Change it in .env (GRYPHOS_ALLOWED_TARGETS) and restart; the model cannot modify it.[/dim]"
    )


def _cmd_status(state: AppState) -> None:
    last = state.last_session
    table = Table(title="Gryphos status", show_header=False)
    table.add_column("Key", style="cyan")
    table.add_column("Value")
    table.add_row("Model", state.llm.model)
    table.add_row("Scope", ", ".join(state.settings.allowed_targets))
    table.add_row("Last target", state.last_target or "(none)")
    table.add_row("Step limit", str(state.settings.max_agent_steps))
    table.add_row("Time budget", f"{state.settings.time_budget_seconds}s")
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
    state.console.print("[dim]Inspect one with: report <session-id>[/dim]")


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
    table.add_column("Network", justify="center")
    table.add_column("Risk")
    table.add_column("Approval")
    table.add_column("Description")
    for spec in state.registry.values():
        table.add_row(
            spec.name,
            "yes" if spec.network_active else "no",
            spec.risk,
            spec.approval_policy,
            spec.description[:70] + ("…" if len(spec.description) > 70 else ""),
        )
    state.console.print(table)
    state.console.print(
        "[dim]Only these tools can ever execute. The model cannot invent commands or tools.[/dim]"
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

    if target:
        try:
            target = validate_target(target, settings.allowed_targets)
            state.last_target = target
        except ScopeError as exc:
            state.console.print(f"[red]Target rejected:[/red] {exc}")
            return

    session = Session(
        session_id=new_session_id(),
        objective=objective,
        scope_snapshot=settings.allowed_targets,
        model=state.llm.model,
    )
    outcome = run_agent(
        state.llm, settings, objective, target,
        registry=state.registry, session=session, console=state.console,
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
        f"Scope: [cyan]{', '.join(settings.allowed_targets)}[/cyan]"
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
