# Contract-sensitive renames

Classify the identifier before changing it. A private implementation name may
be local, while the same text in serialization, configuration, queries, or stored
data may be part of a durable contract.

## Identify the consumers

Inspect relevant callers, schemas, serialized payloads, persisted records,
external integrations, generated clients, dashboards, alerts, and operational
procedures. Use evidence from the owning repositories rather than assuming a
search in one file finds every consumer.

A route, database column, public type, event name, metric label, or configuration
key can affect behavior even when the edit looks like spelling. Determine whether
old data or clients still use the old name and whether versioning or deprecation
rules apply. Do not silently change published identifiers during prose cleanup.

## Use the authorized migration scope

If the user approved the rename and its necessary forward migration, carry it
through the existing migration and release process without asking for the same
permission again. If the work requires unapproved data changes, external-system
changes, or a broader interface migration, describe that scope and seek only the
missing decision. Continue independent authorized work.

Move the owning contract and affected consumers to the canonical identifier
coherently. Use the existing forward migration mechanism for stored data and
remove superseded paths within the authorized scope. Do not add aliases,
dual read/write protocols, legacy adapters, or speculative compatibility layers.

Preserve ownership and rollout ordering. Verify the current user flow, migrated
records, and affected examples. A green compile does not prove that an external
consumer uses the current contract or that migrated records can be read.

## Report what changed

State the old and new names, affected contracts, forward migration, and
verification relevant to the task. Update current documentation and generated
outputs where required. Preserve useful history; do not rewrite old evidence to
pretend the new identifier always existed.

If only prose changed, report it as a prose change. If a migration is incomplete,
name the remaining consumers or unknowns instead of declaring the rename complete.
