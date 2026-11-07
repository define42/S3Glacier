package autoclean

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"glacier/archive"
	"glacier/config"
	"glacier/prometheus"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/disk"
)

func getDiskUsageAllowed() float64 {
	allowedDiskEnv, err := strconv.ParseFloat(os.Getenv("DISK_USAGE_ALLOWED"), 64)
	if err != nil {
		allowedDiskEnv = 75
	}
	if math.IsNaN(allowedDiskEnv) || allowedDiskEnv < 5 || allowedDiskEnv > 99 {
		fmt.Println("DISK_USAGE_ALLOWED not accepted. Only 5-99 is allowed; using 75")
		allowedDiskEnv = 75
	}
	return allowedDiskEnv
}

// DiskUsageAllowed is the shared disk usage threshold in percent, read from
// DISK_USAGE_ALLOWED at package initialization. Values outside 5 through 99 or
// invalid values fall back to 75; changing the environment later has no effect.
var DiskUsageAllowed = getDiskUsageAllowed()

type archiveCandidate struct {
	path    string
	hour    time.Time
	hasData bool
}

// archiveHour accepts only the bucket archive layout.
// Paths are relative to DATA_FOLDER, so metadata and unrelated tar files cannot
// become cleanup candidates merely by containing a date somewhere in the path.
func archiveHour(relative string) (time.Time, bool) {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) != 7 || parts[0] != "buckets" || parts[1] == "" {
		return time.Time{}, false
	}
	parts = parts[2:]
	if len(parts) != 5 || len(parts[4]) <= len(".tar") || filepath.Ext(parts[4]) != ".tar" {
		return time.Time{}, false
	}
	date := strings.Join(parts[:4], "/")
	hour, err := time.Parse("2006/01/02/15", date)
	if err != nil || hour.Format("2006/01/02/15") != date {
		return time.Time{}, false
	}
	return hour, true
}

func collectArchives(root string) ([]archiveCandidate, error) {
	byPath := make(map[string]archiveCandidate)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			first, _, _ := strings.Cut(filepath.ToSlash(relative), "/")
			if relative != "." && first != "buckets" {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		archivePath, metadata := archive.MetadataArchive(path)
		if metadata {
			relative, err = filepath.Rel(root, archivePath)
			if err != nil {
				return err
			}
		} else {
			archivePath = path
		}
		hour, ok := archiveHour(relative)
		if !ok {
			return nil
		}
		candidate := byPath[archivePath]
		candidate.path, candidate.hour = archivePath, hour
		candidate.hasData = candidate.hasData || !metadata
		byPath[archivePath] = candidate
		return nil
	})
	if err != nil {
		return nil, err
	}
	candidates := make([]archiveCandidate, 0, len(byPath))
	for _, candidate := range byPath {
		candidates = append(candidates, candidate)
	}
	// Bucket names must not affect retention: evict the oldest hour across all
	// buckets, using the full path only to make ties deterministic.
	slices.SortFunc(candidates, func(a, b archiveCandidate) int {
		if order := a.hour.Compare(b.hour); order != 0 {
			return order
		}
		return cmp.Compare(a.path, b.path)
	})
	return candidates, nil
}

func removeArchive(path string) (bool, error) {
	return archive.Default.TryDelete(context.Background(), path)
}

func cleanupArchives(candidates []archiveCandidate, allowed float64, diskUsage func() (float64, error)) ([]archiveCandidate, error) {
	retained := make([]archiveCandidate, 0, len(candidates))
	var measurementErr error
	stopEvicting := false
	for _, candidate := range candidates {
		if !candidate.hasData {
			// Recheck absence under the archive key lock. A new writer may have
			// recreated this path after collection; it must not be evicted here.
			reaped, err := archive.Default.TryReapOrphan(context.Background(), candidate.path)
			if err != nil && !errors.Is(err, archive.ErrBusy) {
				fmt.Printf("Checkpoint cleanup skipped %q: %v\n", archive.CommitPath(candidate.path), err)
			}
			if !reaped {
				retained = append(retained, candidate)
			}
			continue
		}
		if stopEvicting {
			retained = append(retained, candidate)
			continue
		}
		used, err := diskUsage()
		if err != nil {
			// Without a fresh measurement, leave every remaining archive intact.
			measurementErr, stopEvicting = err, true
			retained = append(retained, candidate)
			continue
		}
		if math.IsNaN(used) || math.IsInf(used, 0) || used < 0 || used > 100 {
			measurementErr, stopEvicting = fmt.Errorf("invalid disk usage: %v", used), true
			retained = append(retained, candidate)
			continue
		}
		if used <= allowed {
			stopEvicting = true
			retained = append(retained, candidate)
			continue
		}
		removed, err := removeArchive(candidate.path)
		if errors.Is(err, archive.ErrBusy) {
			err = nil
		}
		if err != nil {
			fmt.Printf("Cleanup skipped %q: %v\n", candidate.path, err)
		}
		if removed {
			fmt.Printf("AutoDelete: %v disk usage %.2f%% > %.2f%%\n", candidate.path, used, allowed)
		} else {
			retained = append(retained, candidate)
		}
	}
	return retained, measurementErr
}

func dataWindowHours(candidates []archiveCandidate, now time.Time) float64 {
	for _, candidate := range candidates {
		if !candidate.hasData {
			continue
		}
		return max(0, now.Sub(candidate.hour).Hours())
	}
	return 0
}

func runCleanup(root string, allowed float64, diskUsage func() (float64, error), now time.Time) error {
	candidates, err := collectArchives(root)
	if err != nil {
		return err
	}
	retained, err := cleanupArchives(candidates, allowed, diskUsage)
	prometheus.Current_data_window_in_hours.Set(dataWindowHours(retained, now))
	return err
}

// AutoClean runs disk-pressure cleanup until the process exits. Each pass scans
// all buckets and removes the oldest unlocked archives until fresh disk usage
// is at or below DiskUsageAllowed. Orphan checkpoints are reaped independently
// of disk pressure and do not affect the data-window metric. Busy archives are
// skipped, errors are logged, and the next pass starts after a ten-second pause.
// Call it in a goroutine.
func AutoClean() {
	fmt.Println("AutoClean start")
	for {
		root := config.Settings.Get(config.DATA_FOLDER)
		diskUsage := func() (float64, error) {
			usage, err := disk.UsageWithContext(context.Background(), root)
			if err != nil {
				return 0, err
			}
			return usage.UsedPercent, nil
		}
		if err := runCleanup(root, DiskUsageAllowed, diskUsage, time.Now()); err != nil {
			fmt.Printf("Cleanup failed for %q: %v\n", root, err)
		}
		time.Sleep(10 * time.Second)
	}
}
