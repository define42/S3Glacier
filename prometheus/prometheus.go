package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"time"
	"context"
	"glacier/config"
	"github.com/shirou/gopsutil/disk"
)

var (
	RawUploadProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rawupload_processed_total",
		Help: "The total number of rawupload events",
	})
	RawUploadDoneProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rawupload_processed_total_done",
		Help: "The total number of rawupload events done",
	})
	Disk_free = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "disk_free",
		Help: "The total number of rawupload events done",
	})
	Disk_used_percent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "disk_used_percent",
		Help: "The total number of rawupload events done",
	})
	Tar_files_open = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "tar_files_open",
		Help: "The total number of rawupload events done",
	})
	Current_data_window_in_hours = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "current_data_window_in_hours",
		Help: "Current data time-windows in hours",
	})
)

var ctx = context.Background()

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
