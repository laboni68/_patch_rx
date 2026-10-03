# Benign inputs

Pre-generated benign inputs for the DeepDiff pipeline.

**These exist so you can reproduce the paper's numbers without re-running the
input generators.** Producing them originally meant running neuro-symdiff over
the corpus, plus the pipeline's own mutation, boundary and LLM-agent
generators; the results of all of that are checked in here.

| | |
|---|---|
| Inputs | 4,424 `.bin` |
| Tasks covered | all 118 of the corpus's tasks |
| Generators | 6 (see below) |
| Size | 102 MB on disk (~6 MB packed) |

| Generator | Inputs | Tasks |
|---|---|---|
| neuro-symdiff witnesses | 3,599 | 106 |
| neuro-symdiff, earlier run | 252 | 84 |
| boundary search | 216 | 56 |
| mutation, patch-aware | 128 | 66 |
| LLM agent (`agentic`) | 105 | 105 |
| LLM agent, harness-aware (`agent_decoded`) | 96 | 96 |
| mutation, patch-blind | 28 | 28 |

## Layout

Mirrors `patches/` — one directory per task, holding every input generated for
it, whatever the generator:

```
benign_inputs/<project>/<task>/*.bin
```

The filename identifies the generator, and a matrix column is labelled by the
filename that produced it. The dominant kind is the neuro-symdiff witness
input:

```
benign_inputs/binutils/arvo_54667/benign_neuro_patch_3_witness_cp_2.bin
```

- `<variant>` is `ref` or `1`…`6`, naming the patch whose witness produced this
  input. Every variant referenced by such a filename exists in `dataset.json`
  for that task.
- `<phase>` is the neuro-symdiff analysis mode: **`cp`** = crash-path-only,
  **`ap`** = all-paths.
- `<k>` is the config index, 1–6. The verifier ran 12 configs (`cp` and `ap`
  × k=1…6), each voting independently, so one patch can yield several inputs.

Counts for that kind: 1,905 `cp`, 1,694 `ap`.

`manifest.json` lists every task with its input filenames, a per-task count by
generator, and — for tasks whose witness inputs came from a
`subset_cyberGym_151_*_witness.tar` batch — which batch that was.

## Where these fit among the generators

Inputs come from six generators. They are distinguishable by filename, and a
matrix column is labelled by the filename that produced it.

| Filename | Generator | How the input is chosen |
|---|---|---|
| `benign_neuro_patch_<v>_witness_<ap\|cp>_<k>.bin` | neuro-symdiff witnesses, converted offline | from a witness explaining why a patch is wrong |
| `benign_neuro_patch_<N>.bin` | neuro-symdiff, earlier run | same idea, flatter naming, before the per-config suffix existed |
| `agentic_poc_<model>.bin` | LLM agent | the agent is asked for an input that exercises the patched code without crashing |
| `agent_decoded_<model>.bin` | LLM agent, harness-aware | same, but the agent is shown the fuzz harness so it can emit a structurally valid input |
| `benign_poc<N>.bin` | `--gen-benign N` | patch-blind mutation: must not crash the vulnerable build and must reach the target |
| `benign_patch_poc<N>.bin` | `--gen-patch-poc N` | mutation, but must additionally reach the *patched* code (non-empty trace on p0) |
| `benign_boundary_poc<N>.bin` | `--boundary` | binary-searches the largest length-field value that still does not crash, then samples at that boundary |

`--boundary` inputs involve no model, despite the `agent` name they carry in
older runs: they are a deterministic binary search over a length field. They
exist to catch off-by-one and under-restrictive patches, which plain mutation
inputs miss because those sit deep inside the safe region.

> **Naming mismatch in the shipped code.** `gen_benign.py` writes boundary
> inputs as `benign_boundary_poc{N}.bin` (`boundary_prefix`, line 1112) and
> offers no prefix override, but `deepdiff_pipeline.sh` collects boundary
> columns with `ls -1 /output/benign_poc_agent_p*.bin` (line 1239) and never
> mentions `benign_boundary` at all. As shipped, `--boundary` therefore
> generates inputs that never become matrix columns. The older
> `benign_poc_agent_p*` name is what the checked-in reference runs use.

The two `agent` kinds are genuine LLM output (the runs here used
`claude-opus-4.6`), unlike boundary inputs, whose `agent` name is a misnomer.
`matrix_classify.py` scores them as their own categories — see
`--only-agentic`, `--only-agent-decode` and `--only-agent-inputs`.

Eight `benign_poc_agent_p*.bin` under the old boundary name also ship with the
reference runs in [`../examples/reference_runs/`](../examples/reference_runs),
alongside one `benign_poc1` and one `benign_patch_poc1`.

## Using them

The driver takes a directory and uses every `*.bin` in it, skipping generation:

```bash
scripts/deepdiff_pipeline.sh \
  --task-dir "$CYBERGYM/projects/binutils/arvo_54667" \
  --benign-dir "$PWD/benign_inputs/binutils/arvo_54667"
```

This is the `--benign-dir DIR` flag ("use EVERY `*.bin` already in DIR as
inputs"). It bypasses `gen_benign.py` entirely, so the run is deterministic
with respect to the input set.

See [`../docs/RUNNING_AN_EXAMPLE.md`](../docs/RUNNING_AN_EXAMPLE.md) for the
full end-to-end walkthrough, and [`../examples/`](../examples/) for two
complete reference runs.

## Coverage caveat

Every one of the 118 corpus tasks has at least one input here, but coverage is
uneven *across generators*: 106 tasks have neuro-witness inputs, while the
mutation, boundary and agent kinds reach fewer (see the Tasks column above).
Check `kinds` in `manifest.json` before assuming a task has a particular kind.

Two tasks — `ghostscript/arvo_43268` and `ghostscript/oss-fuzz_391934080` — are
covered only by the `agentic` and `agent_decoded` generators, with two inputs
each. To widen a thin task, fall back to the pipeline's own `gen_benign.py`
(the default when `--benign-dir` is omitted).

## Provenance

Two sources, both verbatim:

- The 3,599 neuro-witness inputs come from the
  `subset_cyberGym_151_*_witness.tar` archives on the
  `dump-gcr-state-2-deepdiff` branch of the internal `deepfix` repository.
- The remaining 825 come from the `subset_cyberGym_15_{1,2,3,4}.tar` and
  `subset_cyberGym_151_ghostscript.tar` run archives and a
  `subset_cyberGym_151` run directory — the full pipeline working trees, of
  which only the task-level `*.bin` were taken.

Files byte-identical to one already present for the same task were dropped (82
across the two sources), as were inputs for the 17 tasks not in this corpus.
Transient `.benign_poc_boundary_candidate.bin` scratch files written during
boundary search were skipped.

Only the generated `.bin` files were taken; the surrounding CyberGym task data
(`poc.bin`, `src.tgz`, `crash.log`) is deliberately **not** included, since
that is redistributed by CyberGym-E2E itself.

The matrices from those runs (`matrix_result.txt`) are **not** checked in: most
predate the final corpus and score patch sets the corpus no longer matches.
