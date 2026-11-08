// Package archive coordinates TAR reads, durable appends, recovery, and eviction.
// One process must own a data directory. Locks are held in memory per full TAR
// path; checkpoints identify the committed prefix independently of the footer.
// Appends and recovery do not scan sibling files. Periodic cleanup supplies
// discovered temporary checkpoint names for coordinated, durable removal.
// Object listings capture immutable committed prefixes without holding archive
// locks during scans. A lazy, byte-bounded metadata cache refreshes from appended
// suffixes; oversized archives use bounded page collectors. Every listing still
// validates the durable checkpoint and rejects a deleted or replaced generation.
package archive
