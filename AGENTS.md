# Using victory-doctor from an agent or script

If you triage VIctory run reports, review crash logs, or help someone whose run failed, this tool gives you the failure list and the matching public reports in one step. It also tells you whether a failure is already reported, so you don't open a duplicate.

## The calls

```
python victory_doctor.py scan <log> --json -          # failures + matches, JSON on stdout
python victory_doctor.py compare <A> <B> --json        # two runs: performance, failures new/gone, settings changed
python victory_doctor.py stats --json [--gpu 4060]     # the shared runs dataset, summarised
python victory_doctor.py selftest                      # parsers check, no network
```

Progress messages go to stderr; stdout is only the JSON.

`scan --json -` returns:

```json
{
  "tool": "victory-doctor 0.2.0",
  "log": "run.log",
  "signatures": [
    {
      "number": 1,
      "kind": "crash",
      "key": "crash 0xc0000005 at image+0x23cf683",
      "title": "Crash: access violation at image+0x23cf683 (write 0x0)",
      "count": 2,
      "status": "fix proposed",
      "matches": [{"repo": "Marvisak/VIctory", "number": 1118, "pr": false, "merged": false,
                   "state": "open", "title": "...", "url": "...", "comments": 26}],
      "excerpt": ["...the log lines around it, user names and paths removed..."],
      "details": {"hashes": ["..."]}
    }
  ]
}
```

`status` is one of `new`, `known, open`, `known, closed`, `fix proposed` (an open PR mentions it), `fix merged`, or `not checked` (lookup skipped or offline). `key` is stable across runs and builds: compare runs by it.

## Before posting anything

- **`status` is not `new`:** someone has reported it. Add the new information (hardware, build, settings, frequency) to the best match instead of opening another issue. `comment N --issue <n>` drafts that comment.
- **`new`:** `draft N` writes an issue body with the excerpt, environment and the searches that came back empty.
- Leave posting to the person whose run it is: `post` and `submit` open GitHub's form for them to check and send.
- Excerpts are already stripped of user names, home folders and computer names. Never add game files or memory dumps (VIctory's asset policy).

## The runs dataset

`https://raw.githubusercontent.com/shawshanker18/victory-runs/main/data/runs.jsonl`: one run per line. Fields: `machine`, `emulator`, `settings` (every `VICTORY_*`), `performance` (`reached`, `fps_median`, `fps_p10`, `fps_p90`, `ms_median`, `gpu_ms_median`, `draws_median`), `failures`. Use it to answer "what fps does this GPU get", "which settings helped", "who else hits this failure".

## Limits

- GitHub search without a token allows 10 queries a minute; the tool spaces them and caches results for 12 hours. Set `GITHUB_TOKEN` for 30 a minute.
- Matching is by search terms (offsets, error codes, message phrases, shader hashes), so a match means "mentions it", not "is the same bug". Read the top match before you conclude.
