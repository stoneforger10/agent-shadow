# Security invariants

- Action and certificate IDs are immutable.
- Action hashes bind simulations to exact proposed operations.
- Validators refetch context and compare the complete record exactly.
- Unavailable or ambiguous context never yields `ALLOW`.
- Critical impact or intent divergence deterministically blocks execution.
- Irreversible actions require independent human review.
- Reviewer and actor addresses must differ.
- Cancellation immediately closes the execution gate.
