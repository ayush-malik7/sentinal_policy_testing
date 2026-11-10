# Same-basename witness and name-fault comparison

Recorded: 2026-11-11. Two fresh seven-case trials compared the correct file-object rule, full-path mutant and requested-basename mutant on the real lab kernel. This is fixed diagnostic evidence, not random/guided evaluation.

## New witness and unchanged contract

The allowed program is program_a. The target is a fresh copy at other/program_a. They have equal basenames, different full paths and different file identities. Both are controlled native ELF files on one device. The allowed object is kept open for the trial. Copy setup finishes before exec; the existing file-object model independently predicts DENY, agreeing with the fixture's fixed expectation.

| Recorded trial | Workload cgroup ID | Allowed identity | Target identity |
|---|---:|---|---|
| 1 | 13106 | major=8, minor=2, inode=3670097 | major=8, minor=2, inode=3670098 |
| 2 | 13124 | major=8, minor=2, inode=3670097 | major=8, minor=2, inode=3670098 |

The trial directories were /tmp/sentinel-basename-7we67572/trial-1-q1djbncm and /tmp/sentinel-basename-7we67572/trial-2-_oxjop_g. Within each, the witness files were deny_same_basename/program_a and deny_same_basename/other/program_a. These are historical paths, not remaining files or reusable bindings.

## Controls and independent measurements

Each trial first executes all seven fixtures without Sentinel enforcement. It then loads the correct control, full-path mutant and basename mutant one at a time, detaching between phases. All three share a 160-byte policy value: the 16-byte identity, pathname[128] and basename[16]. The correct control ignores the name fields and preserves the original device/inode comparison.

The basename mutant reads bprm->filename, finds the last slash using a bounded reverse scan, reads the final component into a separate 16-byte buffer, and compares that name with the original A basename. Registered paths and basenames are qualified at no more than 126 and 14 bytes respectively. Pointer/string errors and truncation invalidate the experiment. Scope and incoming-BPF-return gates remain in the source.

All model expectations stay unchanged. An actual ALLOW requires the correct native ELF marker, exit 0 and no exec error. An actual DENY requires EPERM from exec, no marker and harness exit 125. BPF decision logs are not the outcome oracle. Every mismatch is collected before checking the known planted-fault signature; this signature is not a generator.

## Observed seven-case matrix

| Case | Model | Correct control | Full-path mutant | Basename mutant |
|---|---|---|---|---|
| allow_original | ALLOW | ALLOW | ALLOW | ALLOW |
| deny_other | DENY | DENY | DENY | DENY |
| allow_symlink | ALLOW | ALLOW | DENY: mismatch | DENY: mismatch |
| allow_renamed | ALLOW | ALLOW | DENY: mismatch | DENY: mismatch |
| deny_copy | DENY | DENY | DENY | DENY |
| allow_outside_scope | ALLOW | ALLOW | ALLOW | ALLOW |
| deny_same_basename | DENY | DENY | DENY | ALLOW: mismatch |

This pattern repeated in both trials. On the new seventh case the full-path and basename mutants differ, so the witness distinguishes them. Both mutants already failed at fixed-sequence position 3; the seventh case does not show faster first detection.

| Measurement | Across both trials |
|---|---|
| Baseline successes | 14/14 |
| Correct-reference matches | 14/14 |
| Full-path checks | 14; four false-denial observations |
| Basename checks | 14; four false denials plus two false allows |
| Controlled fixture exec attempts | 56 |

The earlier ignore-inode mutant was not run on this new seventh case. Its existing six-case results must not be extrapolated into an observed seven-case column.

## Repeated inode numbers and lifetime

The same numeric inode values appeared again in trial 2 after trial 1's policies detached, pinned descriptors closed and temporary files were removed. Trial 2 creates new fixture paths, reads identities again and binds the fresh workload ID. During each trial, the allowed and target files have different identities and the allowed file remains open for the policy lifetime.

Numeric recurrence between completed fixture lifetimes does not invalidate the within-trial witness. It does not demonstrate a stale-policy collision, a bypass while A is pinned, or a new inode-reuse vulnerability. Retaining an allowed identity after the allowed object is deleted and unpinned is not tested and remains outside v0. The [unlink manual](https://man7.org/linux/man-pages/man2/unlink.2.html) explains the open-file lifetime rule.

## Lab, source and cleanup

- SentinelLab, Ubuntu 24.04; run printed kernel 6.8.0-149-generic. Recorded system BCC packages are 0.29.1+ds-1ubuntu7.
- Controller: /system.slice/sentinel-enforcement-check.service/controller. In-scope children entered the fresh workload group; the outside-scope control did not.
- All six policy probes detached, both workload groups were removed and service exit status was 0. No identity/name read error invalidated a case.
- Whole-service runtime was 24.261 seconds, including all setup, compilation, baselines, policy phases and cleanup. This is not policy overhead or an inter-diagnostic speed comparison.
- The preceding pathname checkpoint was 8ce2650. The checkpoint containing this record also includes mutant_basename_check.py.

The successful run demonstrates the three generated programs' BCC compilation and verifier acceptance on this lab kernel, including the 160-byte map layout and bounded basename parsing. It does not establish arbitrary-path or other-kernel behaviour.

## Reproduce and next work

Keep mutant_basename_check.py beside enforcement_check.py, mutant_inode_check.py, mutant_path_check.py, policy_model.py and scope_handle_check.py in ~/runtime-sentinel. Root, the verified kernel, active BPF-LSM, system BCC, matching headers, a C compiler and cgroup v2 delegation are required.

    sudo systemd-run --unit=sentinel-enforcement-check --uid=root --wait --pipe --collect --property=Delegate=yes --property=DelegateSubgroup=controller --property=RuntimeMaxSec=90s /usr/bin/python3 -u "$HOME/runtime-sentinel/mutant_basename_check.py"

The 90 seconds is a maximum service runtime. Existing source and persistent boot settings are not changed. Check detachment/removal messages and successful exit as well as the summary.

Three planted fault families now have kernel witnesses across the recorded diagnostics. This is not a general mutation score, a vulnerability finding, a novel technique or a seeded comparison. Next, specify shared valid inputs, model-derived coverage features and equal-budget pilot rules before implementing random/guided selection; broaden the supported fault set afterward. Actual earlier-denial composition remains untested. Any future scope-removing mutant requires an independent immutable experiment boundary first.
