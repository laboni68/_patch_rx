# DeepDiff: Neuro-Dynamic Regression-Freedom Checking for Security Patch Validation

## Dataset
The patch corpus used in the DeepDiff paper: 630 candidate patches across 118 vulnerabilities from 40 open-source projects, derived from [CyberGym-E2E](https://github.com/sunblaze-ucb/cybergym-e2e).
The patches are saved in the ```patches``` folder.

## Metadata
- ```cybergym_630.xlsx``` contains the results of the CyberGym evaluation pipeline (testing with triggering input TT and developer written/unit tests RT).
- ```developer_written_sem_eq.txt``` contains the list of 134 patches which are wither developer written or semantically equivalent to them.
- ```filter_benign_input.txt``` contains the list of the discarded benign inputs which trigger vulnerability in the vulnerable code.

## scripts
- ```deepdiff_pipeline.sh``` is the script for running the dynamic analysis pipeline of our regression-freedom checking approach which uses internally other scripts like ```gen_benign.py``` and ```instrument_writes.py``` files.
- Requires Docker with access to the OSS-Fuzz base images. Reading a matrix:
`benign = EQUIVALENT` means it preserves valid-input behaviour; a good patch is EQUIVALENT on every benign input.


#### Metrics

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

The confusion matrix this corpus encodes (`correct` vs `validation_passed`) is
TP 245, FN 251, FP 1, TN 133, giving recall_bad 0.4940, precision_good 0.3464,
macro F1 0.5869, and a false-alarm rate of 1/134. `validation_metrics.py`
reports the validation-stage breakdown and additionally needs `openpyxl`.


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

  



