# Terminal UI

`sondera tui` is a read-only view over a running server's console surface:

```bash
cargo run -p sondera -- tui
```

It opens on the **run feed** — verdict, agent, status, event count, duration,
and the digest summary for every recorded run, kept current over
`StreamTrajectories`. `Enter` opens that run's **transcript**: a tree of steps
on the left, with each action's output nested beneath it, and the selected event
in full on the right — prompts rendered as markdown, shell as shell, file writes
in the language of the file, and tool payloads as JSON, followed by the
adjudication and the scanner's read of it.

| Key | Action |
|-----|--------|
| `↑` `↓` / `j` `k` | Move through runs or steps |
| `Enter` | Open a run; fold or unfold a step |
| `Tab` | Switch between the tree and the detail pane |
| `n` | Jump to the next deny or escalate |
| `E` / `C` | Expand or collapse every step |
| `/` | Filter the feed (agent, id, status, summary) |
| `r` | Refresh the current screen and restart its stream |
| `t` | Toggle light and dark |
| `Esc` | Back to the feed |

It dials `http://127.0.0.1:50051` by default — override with `--endpoint` or
`SONDERA_CONSOLE_ENDPOINT`. `--filter` accepts the console's clause grammar
(`agent=agents/{id}`, `decision=deny`, `status=running`). `--no-live` reads an
opened transcript as a snapshot; `r` reloads it. The theme honours `NO_COLOR`
and `SONDERA_THEME`.
