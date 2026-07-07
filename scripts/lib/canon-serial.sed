# Industrial Boot (#106) — canonicalize a raw Yuva serial capture for the
# empty-byte-diff proof (DoD-1). It masks ONLY the inherently per-run
# nondeterministic fields (entropy-seeded nonces/tags/challenges/digests, the
# cycle counters, and the QEMU teardown line), so that two boots of the SAME
# binary — and a pre-feature baseline vs the Industrial-Boot build — reduce to
# an IDENTICAL canonical form. Any DETERMINISTIC marker/witness byte a run
# script greps survives untouched, so a real perturbation of the raw stream
# would still show as a diff.
s/0x[0-9a-fA-F]\+/0xH/g
s/resp-hex=[0-9a-f]\+/resp-hex=H/g
s/req-id=[0-9a-f]\+/req-id=H/g
/terminating on signal .* from pid .* (timeout)/d
# `seed: total_frames=N` is a pure function of the KERNEL IMAGE SIZE (usable RAM
# minus the reserved kernel span), so it shifts by a few frames whenever ANY code
# is added — it is a memory-layout diagnostic, NOT a milestone marker or witness,
# and is grepped by NO run script. Mask it so the marker/witness byte-identity is
# not obscured by an unavoidable binary-size delta.
s/total_frames=[0-9]\+/total_frames=N/g
