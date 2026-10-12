# CTF challenges

Each challenge is a self-contained directory:

```
challenges/<id>/challenge.json
challenges/<id>/<provided files...>
```

Run one in the CLI with:

```
solve <id>
```

`solve` with no id lists the challenges found here. The solver is confined to the
challenge directory: it can only read files inside it (the `challenge_file`
tool), never the wider filesystem, and it makes no network activity by itself.

## challenge.json fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes* | Challenge id (letters, digits, `.`, `_`, `-`). Must match the directory name. |
| `name` | no | Display name (defaults to the id). |
| `category` | yes | One of: `misc`, `encoding`, `crypto`, `forensics`, `stego`, `web`, `network`, `reverse_engineering`, `binary_exploitation`. |
| `description` | no | Background shown to the solver. |
| `task` | no | What must be done. |
| `flag_format` | no | A regex the flag must fully match. Omit to use the built-in default (`flag{...}`, `ctf{...}`, etc.). |
| `submit` | no | Optional CTFd-style `{"url", "token", "field"}` for remote verification. Only used when `GRYPHOS_CTF_REMOTE_VERIFY=true`. |
| `files` | no | Explicit provided-file list. If omitted, all files in the directory (except `challenge.json`) are listed. |

\* If `id` is omitted, the directory name is used.

## Honesty model

A flag is only reported as **solved** when a verifier accepts a candidate. String
detection alone (a `flag{...}`-shaped match in a file) is recorded as an
**unverified** candidate, never as success. With the default offline verifier,
acceptance means "matches the declared flag format" and the report says so
explicitly; only a configured submit endpoint yields independent confirmation.

## Remote verification

Remote submission is **off by default**. To enable the CTFd-style verifier for a
challenge that declares a `submit` block, set:

```env
GRYPHOS_CTF_REMOTE_VERIFY=true
```

Only do this for event infrastructure you are authorized to submit to. The
solver still treats a non-accepted candidate as unsolved.
