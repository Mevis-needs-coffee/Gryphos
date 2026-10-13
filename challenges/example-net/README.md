# Example network challenge (template)

This directory is a **template**, not a runnable challenge on its own: it points at
`127.0.0.1`, so start a service on a loopback port first (or edit `target.host`),
then run:

```
solve example-net
```

Only point `target.host` at a system you own or are explicitly authorized to test.
The `target` block is the operator's authorization; without it the solver has **no
network-scan tools at all**.

`lab: true` is required to allow loopback/private/reserved destinations (TryHackMe
machines are reached over a private VPN range, so a real target is normally
`lab: true`). Cloud metadata (`169.254.169.254`), link-local, multicast, and other
blocked ranges are never reachable, even with `lab: true`.

The solver only performs **non-destructive reconnaissance** here — a bounded TCP
port scan, banner/service fingerprinting, and read-only HTTP(S) probes. There are
no exploitation or state-changing actions. Everything is bounded by the declared
port range, connection budget, per-connect timeout, and rate limit.

You can also authorize a target at run time without editing this file:

```
solve example-net --target 10.10.5.12 --lab
```

See `challenges/README.md` for the full `target` block reference.
