# AgentShadow

A reusable GenLayer pre-execution simulation primitive. It binds an immutable
action hash to public context, then validators independently refetch that context
and reproduce an exact SUCCESS/FAILURE/ADVERSARIAL scenario vector.

The contract deterministically derives `ALLOW`, `HUMAN_REVIEW`, or `BLOCK` from
validator-agreed likelihood, impact, divergence, reversibility and evidence
fingerprints. No score, tolerance, free-form summary, or leader-supplied decision
controls state. Missing context is stored as review-required rather than preserving
a positive gate. Human review requires a distinct address registered at creation.
