# gh-runner-harvester

Extract secrets held in the memory of a running **GitHub Actions runner**
(`Runner.Listener`) from the machine it executes on.

When a workflow runs, Actions injects repository/environment/org **secrets**
and matrix/context variables into the runner process. They live in a managed
`Dictionary<String, VariableValue>` inside `Runner.Listener`. This tool reads
them straight out of the process, regardless of whether they were used in a
step.

> ⚠️ **Authorized use only.** This is a post-exploitation / red-team tool. Only
> run it on systems you own or have explicit permission to test.

There are two independent techniques; pick whichever fits your access level.

---

## How it works

GitHub's runner keeps its variables in memory as:

```
System.Collections.Generic.Dictionary<System.String, GitHub.DistributedTask.WebApi.VariableValue>
```

`VariableValue` is a small managed object holding `value` (the string) and an
`isSecret` flag. Both methods below enumerate that structure (precisely, or by
pattern-matching its serialized form) and print every entry where
`isSecret == true`.

---

## Requirements

* Root on the runner host (`ptrace` / `/proc/<pid>/mem` access).
* A .NET runtime providing `dotnet` (method 1 only).
* `python3` (method 2 only).
* Target must have a **live** `Runner.Listener` (i.e. a job currently running,
  or a persistent runner process).

---

## Method 1 — `dotnet-dump` + `frida` (`dump.sh`)

The precise approach. It collects a core dump, finds the real address of the
`VariableValue` dictionary with `dotnet-dump analyze`, injects that address
into `dump.js`, and walks the live dictionary with frida.

```bash
# From a clone of this repo:
./dump.sh

# Or target a specific PID explicitly:
PID=12345 sudo -E ./dump.sh
```

Once the repo is public it can also run as a one-liner (both files are pulled
from GitHub):

```bash
curl -sSf https://raw.githubusercontent.com/hugo-syn/gh-runner-harvester/main/dump.sh | bash
```

Output:

```
[+] Runner PID: 4821
[+] Dictionary address: 0x7f1c00a2b890
[+] Run frida script.
[+] Dictionary Count: 7
- AZURE_CREDENTIALS: {"subscriptionId":"…"} (isSecret: 1)
- DOCKER_PASSWORD: hunter2 (isSecret: 1)
```

### Files

| File      | Role                                                            |
|-----------|----------------------------------------------------------------|
| `dump.sh` | Orchestrates install, PID lookup, heap analysis, frida run.    |
| `dump.js` | Frida script that walks the dictionary and prints secret vars. |

`dump.sh` prefers the `dump.js` sitting next to it; only when piped through
`curl | bash` (no sibling file) does it fetch one from the repo.

---

## Method 2 — memory scrape (`memdump.py`)

Faster and dependency-light (no dotnet, no frida). It reads
`/proc/<pid>/maps` + `/proc/<pid>/mem` and regex-matches the JSON
serialization of each variable:

```bash
sudo python3 memdump.py            # auto-detect Runner.Listener PID
sudo python3 memdump.py 12345      # explicit PID
```

Or the low-tech pipe form (raw memory → `tr`/`grep`):

```bash
sudo RAW=1 python3 memdump.py | tr -d '\0' | \
    grep -Eao '"[^"]+":\{"value":"[^"]*","isSecret":true\}'
```

This is best-effort: it can pick up values that have since been freed, and may
miss entries whose serialization isn't currently resident.

---

## Notes & caveats

* Offsets in `dump.js` (e.g. `countOffset = 0x38`) assume a **64-bit** .NET
  runtime. On 32-bit or unusual runtime versions the dictionary layout may
  differ and `dump.js` needs adjusting.
* Only self-ephemeral secrets are guaranteed gone with the process; a
  long-lived/persistent runner keeps them resident between jobs.
* Consider dropping a dump file off disk (`dump.dmp`) as noisy — this tool
  keeps it in a temp dir and removes it on exit.

---

## References

* Original research and gist by [@hugo-syn](https://gist.github.com/hugo-syn),
  with an alternative technique discovered by **@Tr4LSecurity**.
* Nikita Stupin — earlier research and PoC for extracting secrets from
  self-hosted GitHub Actions runners:
  [@nikitastupin](https://github.com/nikitastupin).
* Karim Rahal — *GitHub Actions leaking secrets*:
  <https://www.karimrahal.com/2023/01/05/github-actions-leaking-secrets/>.
