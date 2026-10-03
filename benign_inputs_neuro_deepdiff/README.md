# Benign inputs

Pre-generated benign inputs for the DeepDiff pipeline, derived from
neuro-symdiff witnesses.

**These exist so you can reproduce the paper's numbers without re-running the
neural verifier.** Generating them originally required running neuro-symdiff
over the corpus and converting each witness into a concrete input; the results
of that step are checked in here.

| | |
|---|---|
| Inputs | 3,599 `.bin` |
| Tasks covered | 106 of the corpus's 118 |
| Variants covered | `ref`, `patch_1` … `patch_6` |
| Size | 85 MB on disk (~4 MB packed) |

## Layout

Mirrors `patches/`:

```
benign_inputs/<project>/<task>/benign_neuro_patch_<variant>_witness_<phase>_<k>.bin
```

For example:

```
benign_inputs/binutils/arvo_54667/benign_neuro_patch_3_witness_cp_2.bin
```

- `<variant>` is `ref` or `1`…`6`, naming the patch whose witness produced this
  input. Every variant referenced by a filename exists in `dataset.json` for
  that task.
- `<phase>` is the neuro-symdiff analysis mode: **`cp`** = crash-path-only,
  **`ap`** = all-paths.
- `<k>` is the config index, 1–6. The verifier ran 12 configs (`cp` and `ap`
  × k=1…6), each voting independently, so one patch can yield several inputs.

Counts: 1,905 `cp`, 1,694 `ap`. Per task: 1 input minimum, 33 median, 77 maximum.

`manifest.json` lists every task with its input filenames and records which
`subset_cyberGym_151_*` run batch it came from. Each task belongs to exactly
one batch — there are no duplicate or conflicting inputs across batches.

## Where these fit among the generators

The pipeline can source benign inputs four ways. They are distinguishable by
filename, and a matrix column is labelled by the filename that produced it.

| Filename | Generator | How the input is chosen |
|---|---|---|
| `benign_neuro_patch_*_witness_*.bin` | neuro-symdiff witnesses, converted offline | from a witness explaining why a patch is wrong — **this directory** |
| `benign_poc<N>.bin` | `--gen-benign N` | patch-blind mutation: must not crash the vulnerable build and must reach the target |
| `benign_patch_poc<N>.bin` | `--gen-patch-poc N` | mutation, but must additionally reach the *patched* code (non-empty trace on p0) |
| `benign_poc_agent_p<N>.bin` | `--boundary` | binary-searches the largest length-field value that still does not crash, then samples at that boundary |

`--boundary` inputs are named `agent` but involve no model: they are a
deterministic binary search over a length field. They exist to catch off-by-one
and under-restrictive patches, which plain mutation inputs miss because those
sit deep inside the safe region.

Only the neuro-witness inputs are checked in at corpus scale. Ten examples of
the mutation and boundary kinds ship with the two reference runs in
[`../examples/reference_runs/`](../examples/reference_runs) — one
`benign_poc1`, one `benign_patch_poc1`, and eight `benign_poc_agent_p*`, for
two OpenSC tasks.

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

12 of the 118 corpus tasks have no benign inputs here, because neuro-symdiff
produced no usable witnesses for them in these batches:

```
binutils/arvo_51010        ghostscript/oss-fuzz_391934080  libxml2/oss-fuzz_417062198
c-blosc2/arvo_27812        libssh/arvo_10486               libxml2/oss-fuzz_417247563
c-blosc2/arvo_30113        libxaac/arvo_62388              lldpd/arvo_52006
ghostscript/arvo_43268     mupdf/arvo_5492                 wireshark/arvo_1268
```

For those tasks, fall back to the pipeline's own `gen_benign.py` (the default
when `--benign-dir` is omitted).

## Provenance

Recovered verbatim from the `subset_cyberGym_151_*_witness.tar` archives on the
`dump-gcr-state-2-deepdiff` branch of the internal `deepfix` repository. Only
the `.bin` files were taken; the surrounding CyberGym task data (`poc.bin`,
`src.tgz`, `crash.log`) is deliberately **not** included, since that is
redistributed by CyberGym-E2E itself.
