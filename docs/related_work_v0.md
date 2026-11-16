# Related work and research position

Added 2026-11-16, after the v0 experiment. This is a targeted narrative
comparison, not an exhaustive systematic review or a claim of priority.
It changes the interpretation and reading context, not the frozen protocol,
code, raw observations or derived v0 measurements.

## What was already established

Testing access-control decisions against expected answers, evaluating tests
with planted faults, and comparing structured testing with random testing
all predate Sentinel. Linux security enforcement and eBPF-based confinement
also have established research histories. The sources below establish this
overlap; a different implementation platform alone does not establish novelty.

### Policy testing, coverage and mutation

Pretschner, Mouelhi and Le Traon [1] combine access-control models,
combinatorial test generation and mutation-based evaluation, including a
comparison against random tests. This is the closest methodological precedent
identified in this review. Sentinel's small experiment belongs in that existing
line of work; it does not introduce its general experimental idea.

Martin and Xie [2] define faults and mutation operators for XACML policies
and investigate test coverage and fault detection. Their mutation target is
the policy representation. Sentinel's three measured faults alter C enforcer
logic. That is a concrete difference in the tested artifact, not evidence that
implementation mutation or policy conformance testing is new.

### Linux enforcement and its correctness

Edwards, Jaeger and Zhang [3] use runtime analysis to investigate authorization
hook placement in LSM. Sentinel instead checks the decisions of a narrow
policy at an existing hook; it does not establish that all necessary kernel
authorization points are covered.

Findlay, Somayaji and Barrera [4] implement process confinement using eBPF,
including LSM hooks, with Python/BCC and restricted C. This precedes Sentinel's
implementation technology. Sentinel's pilot studies test selection for its own
restricted rule rather than proposing a replacement confinement system.

Sun and Su [5] test the correctness of the eBPF verifier. That verifier examines
program safety before loading. Sentinel checks whether an admitted program
enforces the intended application rule. These are different correctness targets;
Sentinel neither reproduces their method nor claims their kernel findings.

### Stateful policies as future work

Galletta's BPFence work [6] describes a formally specified stateful policy
language and compilation into in-kernel monitors. It is relevant before any
claim about a new stateful extension. Adding state alone would not establish
novelty. The available extended report is labelled a preprint; its repository
also links a CCS 2026 conference version. Only its abstract and repository
metadata were assessed for this comparison.

## What the completed Sentinel pilot demonstrates

The [v0 report](pilot_results_v0.md) records one specific implementation and
measurement setup:

- A contract for prepared native ELF execution in one exact cgroup, using
  device major/minor and inode identity while the allowed file stays open.
- A C eBPF-LSM reference enforcer, a Python decision model and three deliberate
  implementation faults concerning inode, requested path and basename checks.
- Userspace marker, exec-error and exit-status observations that are separate
  from the BPF decision logs. The model, reference and fixtures nevertheless
  share a development origin.
- Frozen selection rules, seven known fixture families, four cases per method,
  thirty paired seeds and two fresh confirmations per seed.
- Raw evidence and an offline reader retaining failed-to-detect cases as
  censored observations rather than inventing detection positions.

These describe the artifact and its evidence. This review has not established
that their particular combination is the first of its kind. The pilot is not
a head-to-head evaluation against the cited papers or their implementations.
Their reported outcomes cannot be compared numerically with Sentinel's counts
without common tasks, budgets, fault definitions and measurement procedures.

## How to interpret the result

For this finite development set, guided selection detected each planted fault
within four cases in all thirty seeds. Random detected more seeds by step two
for every fault. The observed finding is a final-budget versus earliness
trade-off. It does not establish that guided testing is generally faster,
that the selector is novel, or that an unknown Linux/product bug was found.

The oracle is state-free. Accumulated semantic coverage changes the next
selection, but kernel outcomes do not drive creation of new filesystem
operation sequences. The broader reactive/stateful direction remains future
work. Lifetime holds and scope controls qualify this experiment; they do not
prove content integrity, permanent inode identity or complete sandboxing.

## Questions for a separately specified next evaluation

Before extending the experiment, define a question whose answer could differ
from the current development-set outcome. Useful candidates include whether
the selector transfers to independently designed cases and fault families,
and how it compares with an explicit pairwise/combinatorial baseline as well
as random selection. A later engine adapter needs a shared, justified contract;
different engines need not implement equivalent policy semantics.

Any new cases, faults, features, budgets or stateful operations need a versioned
protocol and new results. The completed v0 experiment should remain reproducible.
Prior work can guide that design, but this review does not yet establish an
unexplored gap or a publishable novelty claim.

## Review scope and verification limits

The literature check was conducted on 2026-11-16, with discovery from the
preceding discussion. It used targeted web queries, university publication
records, author-hosted papers, the USENIX proceedings page and preprint records.
It prioritised access-control test generation/mutation, Linux authorization
correctness, eBPF confinement and stateful policy enforcement. It was a single
AI-assisted narrative assessment; no exhaustive screening counts or PRISMA
claim are made.

Bibliographic identity and claim support were checked separately. For [1], the
university record and indexed abstract/introduction were available; full-PDF
retrieval was rate-limited. For [2] and [4], author-hosted paper text was
retrieved, with the comparison based on their abstract/introduction and relevant
method descriptions. For [3] and [5], the linked primary publication abstracts
support the limited comparisons. For [6], the abstract and repository metadata
were available, not a full-text assessment. Missing retrieval is not evidence
that a paper lacks a technique. Current search coverage cannot prove absence
of more closely matching research.

## References

1. Alexander Pretschner, Tejeddine Mouelhi and Yves Le Traon. 2008.
   *Model-Based Tests for Access Control Policies.* ICST, pp. 338–347.
   [DOI](https://doi.org/10.1109/ICST.2008.44).
   [University record and abstract](https://portal.fis.tum.de/en/publications/model-based-tests-for-access-control-policies-1/).
2. Evan Martin and Tao Xie. 2007.
   *A Fault Model and Mutation Testing of Access Control Policies.* WWW,
   pp. 667–676. [DOI](https://doi.org/10.1145/1242572.1242663).
   [Author-hosted paper](https://taoxie.cs.illinois.edu/publications/www07.pdf).
3. Antony Edwards, Trent Jaeger and Xiaolan Zhang. 2002.
   *Runtime Verification of Authorization Hook Placement for the Linux
   Security Modules Framework.* CCS.
   [IBM Research publication record](https://research.ibm.com/publications/runtime-verification-of-authorization-hook-placement-for-the-linux-security-modules-framework).
4. William Findlay, Anil Somayaji and David Barrera. 2020.
   *bpfbox: Simple Precise Process Confinement with eBPF.* CCSW, pp. 91–103.
   [DOI](https://doi.org/10.1145/3411495.3421358).
   [Author-hosted paper](https://people.scs.carleton.ca/~barrera/publications/ccsw20-findlay.pdf).
5. Hao Sun and Zhendong Su. 2024.
   *Validating the eBPF Verifier via State Embedding.* OSDI, pp. 615–628.
   [USENIX proceedings and paper](https://www.usenix.org/conference/osdi24/presentation/sun-hao).
6. Letterio Galletta. 2026.
   *Enforcement of In-Kernel Stateful Security Policies via eBPF.*
   Extended report, preprint.
   [Zenodo record](https://doi.org/10.5281/zenodo.22744508);
   [arXiv abstract](https://arxiv.org/abs/2609.13930).

## Assistance and method acknowledgement

This documentation comparison was prepared with AI assistance using K-Dense's
`literature-review` and `scientific-critical-thinking` guidance. That use is not
independent expert peer review or a guarantee of novelty. The guidance was read
from the public repository, not executed through an installed plugin. Sources:
[literature-review](https://github.com/K-Dense-AI/scientific-agent-skills/blob/main/skills/literature-review/SKILL.md)
and [scientific-critical-thinking](https://github.com/K-Dense-AI/scientific-agent-skills/blob/main/skills/scientific-critical-thinking/SKILL.md),
accessed 2026-11-16.

Software/method reference: Timothy Kassis, Vinayak Agarwal, Yuhuan He, Darshil
Patel and Aubrey M. Brueckner. 2026. *Scientific Agent Skills: A Library of
Procedural Knowledge for Research Agents.* arXiv:2609.00065.
[DOI](https://doi.org/10.48550/arXiv.2609.00065). The current arXiv record was
checked on 2026-11-16 (revision dated 2026-09-02).
