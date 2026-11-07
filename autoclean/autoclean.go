package autoclean

import (
	"context"
	"fmt"
	"glacier/config"
	"glacier/prometheus"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
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

var DiskUsageAllowed = getDiskUsageAllowed()

type archiveCandidate struct {
	path string
	hour time.Time
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
	var candidates []archiveCandidate
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if relative != "." && strings.Split(filepath.ToSlash(relative), "/")[0] != "buckets" {
				return filepath.SkipDir
			}
			return nil
		}
		hour, ok := archiveHour(relative)
		if !ok || !entry.Type().IsRegular() {
			return nil
		}
		candidates = append(candidates, archiveCandidate{path: path, hour: hour})
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Bucket names must not affect retention: evict the oldest hour across all
	// buckets, using the full path only to make ties deterministic.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].hour.Equal(candidates[j].hour) {
			return candidates[i].path < candidates[j].path
		}
		return candidates[i].hour.Before(candidates[j].hour)
	})
	return candidates, nil
}

func removeArchive(path string) (bool, error) {
	// Do not create a file if another cleanup pass removed it after the scan.
	fileLock := flock.New(path, flock.SetFlag(os.O_RDWR))
	defer fileLock.Close()
	locked, err := fileLock.TryLock()
	if err != nil || !locked {
		return false, err
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	return true, nil
}

func cleanupArchives(candidates []archiveCandidate, allowed float64, diskUsage func() (float64, error)) ([]archiveCandidate, error) {
	retained := make([]archiveCandidate, 0, len(candidates))
	for i, candidate := range candidates {
		used, err := diskUsage()
		if err != nil {
			// Without a fresh measurement, leave every remaining archive intact.
			return append(retained, candidates[i:]...), err
		}
		if math.IsNaN(used) || math.IsInf(used, 0) || used < 0 || used > 100 {
			return append(retained, candidates[i:]...), fmt.Errorf("invalid disk usage: %v", used)
		}
		if used <= allowed {
			return append(retained, candidates[i:]...), nil
		}
		removed, err := removeArchive(candidate.path)
		if err != nil {
			fmt.Printf("Cleanup skipped %q: %v\n", candidate.path, err)
		}
		if removed {
			fmt.Printf("AutoDelete: %v disk usage %.2f%% > %.2f%%\n", candidate.path, used, allowed)
		} else {
			retained = append(retained, candidate)
		}
	}
	return retained, nil
}

func dataWindowHours(candidates []archiveCandidate, now time.Time) float64 {
	if len(candidates) == 0 {
		return 0
	}
	hours := now.Sub(candidates[0].hour).Hours()
	if hours < 0 {
		return 0
	}
	return hours
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
