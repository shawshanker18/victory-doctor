# victory-doctor

Error diagnosis and comparison for [VIctory](https://github.com/Marvisak/VIctory) runs (GTA VI, Xbox Series, on PC).

Run the game through it, or point it at a log afterwards. It lists every failure in the run, then checks each one against the public issues and pull requests, so you can see at once:

- **Is this new, or are others hitting it too?** Every match is listed with its state.
- **Is there a fix?** `MERGED` (update your build), `PR` (a fix is proposed), `KNOWN` (reported, not fixed), `CLOSED`, or `NEW`.
- **What next?** If others have it, add your details to their report. If you are the first, it drafts the issue for you.

It also keeps a record of every run (hardware, build, settings, frame rates, failures), which you can compare and share. Shared records go into one public dataset that people, scripts and AI models can read: [victory-runs](https://github.com/shawshanker18/victory-runs).

## Install

Python 3.9 or newer, nothing else. Download `victory_doctor.py`.

## Use

Run the game through it. Failures are listed as they happen, and the full diagnosis comes when the game exits:

```
python victory_doctor.py run -- target\release\victory.exe run <game dir>\<title exe> --execute
```

Or diagnose a log you already have. It also reads `crashes.log` and the title's own crash reports for that run:

```
python victory_doctor.py scan run.log
```

Example:

```
[1] PR     Crash: access violation at image+0x23cf683 (write 0x0)  (x2)
       10 report(s) by others; join them with `comment 1 --issue <number>`.
       Marvisak/VIctory#1118 issue open, 26 comments: Crash at victory-image-...dll+0x23cf683 (write 0x0) ~1 min after entering the world
       Marvisak/VIctory#1286 issue open, 7 comments: RTX 4060 Ti (8 GB): ... the remaining +0x23cf683 trap is not a pipeline problem
[7] KNOWN  Warn: host view heap capped at  (x1)
       advice: NVIDIA drivers cap shader-visible heaps at 1,000,000 descriptors; the title asks for 1,245,184 (see the matches).
```

Then:

| Command | What it does |
|---|---|
| `open N` | opens the best match of failure N |
| `comment N --issue 1234` | adds your run's details to someone else's report (copied to the clipboard and the issue opened, or posted with `--api`) |
| `draft N` / `post N` | writes an issue for a new failure and opens GitHub's form filled in; you check it and submit it |
| `compare A B` | two logs or run records side by side: frame rates, failures that appeared or went away, settings that differ |
| `record LOG` | makes a run record from a log (`--setting KEY=VALUE` for what you changed) |
| `submit RUN` | shares a run record in the public runs dataset |
| `stats` | what the shared runs say: frame rates by GPU, the best settings seen, the most common failures |
| `selftest` | checks the parsers |

GitHub lookups work without an account (10 searches a minute). With `GITHUB_TOKEN` set, or the GitHub CLI signed in, they are faster. Results are cached for 12 hours. `--offline` skips them; `--repos` chooses where to search (default: Marvisak/VIctory and fxceless/victory-fork).

## Privacy

- Nothing is posted unless you run `post`, `comment` or `submit` and confirm. `post` and `submit` only open GitHub's form in your browser; you send it.
- Lookups send only the failure's search terms: an offset, an error code, a message's words, a shader hash.
- Drafts and run records have your user name, home folder and computer name taken out.
- No game data is read beyond the logs, and none is sent.

## The runs dataset

Every shared run is one JSON record: machine (CPU, GPUs and drivers, RAM, OS), emulator build and console mode, every `VICTORY_*` setting, frame rates in the world (median, 10th and 90th percentile, GPU time, draws), how far it got, and its failures with their status. They are collected in [`data/runs.jsonl`](https://github.com/shawshanker18/victory-runs/blob/main/data/runs.jsonl), one record per line, which anyone can read:

```
https://raw.githubusercontent.com/shawshanker18/victory-runs/main/data/runs.jsonl
```

## Licence

MIT.
