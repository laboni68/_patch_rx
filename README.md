# DeepDiff: Neuro-Dynamic Regression-Freedom Checking for Security Patch Validation
> **Note:** This repository contains the subset of the artifact. The complete artifact will be released upon receiving the necessary approval.
## Dataset
The patch corpus used in the DeepDiff paper contains **630 candidate patches across 118 vulnerabilities from 40 open-source projects**, derived from [CyberGym-E2E](https://github.com/sunblaze-ucb/cybergym-e2e).

The patches are provided in the `patches` folder. To run the vulnerable projects with our regression-freedom checking approach, the projects should follow the CyberGym data format, with `data` and `projects` subdirectories containing the corresponding `patch_N.diff` or `patch.diff` files.

<!--The patch corpus used in the DeepDiff paper: 630 candidate patches across 118 vulnerabilities from 40 open-source projects, derived from [CyberGym-E2E](https://github.com/sunblaze-ucb/cybergym-e2e). -->
<!--The patches are saved in the ```patches``` folder. To run the vulnerable projects with our regression-freedom checking approach, they need to follow the structure of the cyberGym data format (with data and project sub folder containing the patch_N.diff/patch.diff).-->

## Metadata
- `cybergym_630.xlsx` contains the results of the CyberGym evaluation pipeline, including testing with the triggering input (TT) and developer-written/unit tests (RT).

- `developer_written_sem_eq.txt` contains the list of 134 patches that are either developer-written patches or semantically equivalent to the corresponding developer patch.

- `filter_benign_input.txt` contains the list of discarded benign inputs that trigger the vulnerability in the vulnerable program.

<!-- - ```cybergym_630.xlsx``` contains the results of the CyberGym evaluation pipeline (testing with triggering input TT and developer written/unit tests RT). -->
<!-- - ```developer_written_sem_eq.txt``` contains the list of 134 patches which are wither developer written or semantically equivalent to them. -->
<!-- - ```filter_benign_input.txt``` contains the list of the discarded benign inputs which trigger vulnerability in the vulnerable code. -->

## scripts
- ```deepdiff_pipeline.sh``` is the script for running the dynamic analysis pipeline of our regression-freedom checking approach which uses internally other scripts like ```gen_benign.py``` and ```instrument_writes.py``` files.
- Requires Docker with access to the OSS-Fuzz base images. Reading a matrix:
`benign = EQUIVALENT` means it preserves valid-input behaviour; a good patch is EQUIVALENT on every benign input.
- ```run_all_deepdiff.sh``` runs the ```deepdiff_pipeline.sh``` for the projects. ```scripts/run_all_deepdiff.sh --use-existing-pocs``` will use the existing benign inputs generated to run dynamic analysis (default root folder: subset_cyberGym/projects like cybergym)
- ```bash scripts/run_all_deepdiff.sh --root subset_cyberGym/projects/  --use-existing-pocs``` should run the dynamic analysis with the benign inputs present in the ```data/projects/<project_name>/<vulnerability_folder>/``` (copy all the corresponding benign inputs from the benign_inputs folder)

## benign_inputs
- the benign inputs are concrete benign inputs generated from the candidate witnesses from the neuro-deepdiff (benign_neruro_* format).
- the agent*.bin inputs are generated using neural context (asking agents).
- the rest benign inputs are generated using mutation.

## reference_runs
- this contains the running example results of two projects from opensc where matrix_result.txt contains the result.

## Metrics

`matrix_classify.py` scores the matrices into the reported numbers — incorrect-patch
recall, developer-patch precision, per-class and averaged F1, and the false-alarm
rate. `--adjust-sem-eq` applies the equivalence list checked in at the repo root.

```bash
python3 scripts/matrix_classify.py --base-dir <matrix_dirs> \
    --validation-xlsx metadata/cybergym_validation_151.xlsx \
    --ignore-gt-fail --error-as-discard-patch \
    --filter-non-benign crashing_benign_inputs.tsv \
    --exclude-patches mutated_bad_actually_good.txt \
    --adjust-sem-eq --unbalanced
```

## Example of divergence for an incorrect patch
Example: `binutils/arvo_54667`

The bad patch restricts more inputs than the good patch. In the write diff, the bad patch will not print `curr_srec->sfile` and `curr_srec->srec` for the restricted inputs.

#### Developer Patch

```diff

-		  curr_srec->sfile = data;
-		  curr_srec->srec = module->file_table[data].srec;
+		  if ((unsigned int) data < module->file_table_count)
+		    {
+		      curr_srec->sfile = data;
+		      curr_srec->srec = module->file_table[data].srec;
+		    }
```

#### Incorrect Patch
```diff
-		  curr_srec->sfile = data;
-		  curr_srec->srec = module->file_table[data].srec;
+		  if ((unsigned int) data == module->file_table_count)
+		    {
+		      curr_srec->sfile = data;
+		      curr_srec->srec = module->file_table[data].srec;
+		    }
```

  



