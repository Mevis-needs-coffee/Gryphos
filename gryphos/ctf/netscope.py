"""Runtime scope enforcement for an authorized network CTF target (Phase 4).

`TargetConfig` (see `netconfig.py`) records the one host the operator explicitly
authorized; `NetScope` turns it into an execution-time boundary. Every connection
the solver can open must pass through here, so the model can never widen its own
reach:

- the destination host must match the configured target (a hostname is resolved
  on every connection and **every** resolved address must satisfy the IP policy,
  defeating DNS rebinding to a blocked address);
- the port must fall inside the operator-declared port range and within the
  configured per-scan maximum;
- cloud-metadata and link-local ranges are blocked unconditionally, even in lab
  mode; private/loopback/reserved ranges require the explicit `lab: true`
  opt-in.

`NetScope` performs no I/O beyond DNS resolution; the socket client lives in
`netclient.py` and always consults this object first.
"""

from __future__ import annotations

from .ipguard import AddressPolicyError, check_host
from .netconfig import TargetConfig, TargetConfigError, parse_port_spec


class NetScopeError(ValueError):
    """Raised when a connection violates the authorized target scope."""


class NetScope:
    """The fixed, operator-authorized target boundary for one network challenge."""

    def __init__(self, config: TargetConfig):
        self.config = config
        self.target_host = config.host
        # Fail fast: the configured target itself must satisfy the IP policy.
        self.resolve_destination(self.target_host)
        # Fail fast: the declared default port spec must be valid.
        self.authorize_ports(config.ports)

    # -- properties -------------------------------------------------------

    @property
    def host(self) -> str:
        return self.config.host

    @property
    def lab(self) -> bool:
        return self.config.lab

    @property
    def max_ports(self) -> int:
        return self.config.max_ports

    @property
    def max_connections(self) -> int:
        return self.config.max_connections

    @property
    def connect_timeout_ms(self) -> int:
        return self.config.connect_timeout_ms

    @property
    def min_interval_ms(self) -> int:
        return self.config.min_interval_ms

    @property
    def default_ports(self) -> str:
        return self.config.ports

    def describe(self) -> str:
        return self.config.describe()

    # -- host policy ------------------------------------------------------

    def resolve_destination(self, host: str) -> list[str]:
        """Resolve `host` and verify every address satisfies the IP policy."""
        try:
            return check_host(host, lab=self.lab)
        except AddressPolicyError as exc:
            raise NetScopeError(str(exc)) from exc

    def authorize_host(self, host: str | None) -> str:
        """Validate a requested host against the single authorized target."""
        text = (host or self.target_host).strip()
        if text.lower() != self.target_host.lower():
            raise NetScopeError(
                f"Refused host {text!r}: only the authorized target {self.target_host!r} "
                "may be contacted."
            )
        self.resolve_destination(text)
        return text

    # -- port policy ------------------------------------------------------

    def authorize_ports(self, spec: object | None) -> list[int]:
        """Parse a requested port spec and bound it to the target's declared range."""
        raw = self.default_ports if spec in (None, "") else spec
        try:
            ports = parse_port_spec(raw, self.max_ports)
        except TargetConfigError as exc:
            raise NetScopeError(str(exc)) from exc
        return ports

    def authorize_port(self, port: object) -> int:
        try:
            number = int(port)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise NetScopeError(f"Port {port!r} is not an integer.") from exc
        if not (1 <= number <= 65535):
            raise NetScopeError("Port must be between 1 and 65535.")
        return number
