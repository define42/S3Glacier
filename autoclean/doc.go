// Package autoclean removes whole TAR archives when the data filesystem exceeds
// its shared disk usage threshold. It considers all bucket trees, orders archives
// by their folder hour rather than modification time, and preserves bucket
// definitions. Orphan checkpoints and interrupted checkpoint temporary files
// are reaped independently of disk pressure, after checking under the archive
// lock that no TAR was recreated. There are no per-bucket quotas or minimum
// retention guarantees.
package autoclean
