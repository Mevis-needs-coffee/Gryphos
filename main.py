"""Gryphos entry point.

Run interactively with:  python main.py start
"""

import typer

app = typer.Typer(
    no_args_is_help=True,
    help="Gryphos: approval-based AI security assessment assistant.",
)


@app.callback()
def _root():
    """Gryphos: approval-based AI security assessment assistant."""


@app.command()
def start():
    """Start the interactive Gryphos assistant."""
    from gryphos.cli import run_repl

    run_repl()


if __name__ == "__main__":
    app()
