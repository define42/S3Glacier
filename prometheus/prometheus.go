// Package prometheus registers archive service metrics with Prometheus's default
// registry. Upload handlers and cleanup update the counters and gauges; SystemStat
// polls filesystem capacity after configuration has been initialized.
package prometheus

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/shirou/gopsutil/disk"
	"glacier/config"
	"time"
)

var (
	// RawUploadProcessed counts object upload attempts admitted by HTTP/S3 handlers.
	// A multipart HTTP request can contribute one attempt per file.
	RawUploadProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rawupload_processed_total",
		Help: "The total number of rawupload events",
	})
	// RawUploadDoneProcessed counts new entries after the archive and checkpoint
	// have been committed. Successful identical retries do not increment it.
	RawUploadDoneProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rawupload_processed_total_done",
		Help: "The total number of rawupload events done",
	})
	// Disk_free reports free bytes on the filesystem containing DATA_FOLDER.
	Disk_free = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "disk_free",
		Help: "The total number of rawupload events done",
	})
	// Disk_used_percent reports usage of DATA_FOLDER's filesystem as a percentage.
	Disk_used_percent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "disk_used_percent",
		Help: "The total number of rawupload events done",
	})
	// Tar_files_open counts archive append calls, including lock waits and recovery,
	// but excluding readers and the preceding compression work.
	Tar_files_open = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "tar_files_open",
		Help: "The total number of rawupload events done",
	})
	// Current_data_window_in_hours reports the age of the oldest retained archive
	// folder across buckets. Cleanup sets it to zero when no archives remain or
	// their resolved timestamps are in the future.
	Current_data_window_in_hours = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "current_data_window_in_hours",
		Help: "Current data time-windows in hours",
	})
)

var ctx = context.Background()

// SystemStat polls DATA_FOLDER's filesystem capacity about once per second until the
// process exits. Initialize config.Settings first and run it in a goroutine.
// A failed disk-stat call leaves the previous gauge values unchanged.
func SystemStat() {

	for {
		usageStat, err := disk.UsageWithContext(ctx, config.Settings.Get(config.DATA_FOLDER))
		if err == nil {
			Disk_used_percent.Set(float64(usageStat.UsedPercent))
			Disk_free.Set(float64(usageStat.Free))
		}

		time.Sleep(1000 * time.Millisecond)
	}
}
