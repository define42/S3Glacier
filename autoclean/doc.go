// Package autoclean removes whole TAR archives when the data filesystem exceeds
// its shared disk usage threshold. It considers all bucket trees, orders archives
// by their folder hour rather than modification time, and preserves bucket
// definitions. Each pass collects temporary checkpoint names in one tree walk
// and removes those names under the archive lock, independently of disk pressure.
// Orphan checkpoints are reaped only after checking under the same lock that no
// TAR was recreated. There are no per-bucket quotas or minimum
// retention guarantees.
package autoclean
