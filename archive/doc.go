// Package archive coordinates TAR reads, durable appends, recovery, and eviction.
// One process must own a data directory. Locks are held in memory per full TAR
// path; checkpoints identify the committed prefix independently of the footer.
// Appends and recovery do not scan sibling files. Periodic cleanup supplies
// discovered temporary checkpoint names for coordinated, durable removal.
package archive
