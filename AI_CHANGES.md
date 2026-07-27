# AI Changes

## 2026-07-27 — claude-sonnet-5

Fixed two concurrency bugs found during code review of `viruscan.cc`.

### 1. Use-after-free of the matched virus name

`Item_func_virus_scan::val_str()` read `virus_name` (a pointer into the
ClamAV engine's signature database, set by `cl_scanmap_callback()`) and
`viruscan_signatures` *after* releasing `LOCK_viruscan_engine`. If another
session called `VIRUS_RELOAD_ENGINE()` in that window, `load_engine()`
would swap in a new engine and free the old one, leaving `virus_name`
dangling — a use-after-free reachable by two concurrent `SUPER` sessions
running `VIRUS_SCAN()` and `VIRUS_RELOAD_ENGINE()`.

Fix: copy the matched name and signature count into local variables while
still holding `LOCK_viruscan_engine`, before unlocking. `add_match()` now
takes the signature count as a parameter instead of reading the global
directly, removing an unrelated unsynchronized read too.

### 2. Unsynchronized reload-stat state

`Item_func_virus_reload::val_str()` read, freed (`cl_statfree`), and
reinitialized (`cl_statinidir`) the global `viruscan_signature_stat` /
`viruscan_signature_stat_initialized` with no locking. Two concurrent
`VIRUS_RELOAD_ENGINE()` calls could race on freeing/reinitializing the
same struct, risking a double-free.

Fix: added a dedicated `LOCK_viruscan_reload` mutex serializing the whole
reload body. It's kept separate from `LOCK_viruscan_engine` because
`load_engine()` (called from within the reload path) takes that lock
itself — sharing one mutex here would deadlock.

### Files changed

- `viruscan.cc`

