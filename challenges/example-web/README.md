# Example web challenge (template)

This directory is a **template**, not a runnable challenge on its own: it points at
`http://127.0.0.1:8080`, so start a local service there first (or edit
`web.origin`), then run:

```
solve example-web
```

Only point `web.origin` at a service you own or are explicitly authorized to test.
The `web` block is the operator's authorization; without it the solver has **no
network tools at all**.

`lab: true` is required to allow loopback/private/reserved destinations. Cloud
metadata (`169.254.169.254`), link-local, multicast, and other blocked ranges are
never reachable, even with `lab: true`.

See `challenges/README.md` for the full `web` block reference.
