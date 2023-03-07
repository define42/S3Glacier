package autoclean

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"github.com/shirou/gopsutil/disk"
	"regexp"
	"glacier/config"
	"glacier/prometheus"
	"github.com/gofrs/flock"
)


func getDiskUsageAllowed() float64 {
	allowedDiskEnv, err := strconv.ParseFloat(os.Getenv("DISK_USAGE_ALLOWED"), 64)
	if err != nil {
		allowedDiskEnv = 75
	}
	if allowedDiskEnv < 5 || allowedDiskEnv > 99 {
		fmt.Println("Panic! DISK_USAGE_ALLOWED not accepted. Only 5-99 is allowed")
		allowedDiskEnv = 75
	}
	//fmt.Println("DISK_USAGE_ALLOWED:", allowedDiskEnv, "%")
	return allowedDiskEnv
}

var DiskUsageAllowed = getDiskUsageAllowed()


var ctx = context.Background()

func ExtractDateFromFolder() *regexp.Regexp {
        r, err := regexp.Compile("([0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{2})")
        if err != nil {
                panic(err)
        }
        return r
}

var extractDateFromFolder = ExtractDateFromFolder()

var current_data_time_window_function = func(pathX string, infoX os.DirEntry, errX error) error {

	if errX != nil {
		fmt.Printf("current_data_time_window_function: error 「%v」 at a path 「%q」\n", errX, pathX)
		return errX
	}

	if !infoX.IsDir() {
		if filepath.Ext(pathX) == ".tar" {
			myDate, err := time.Parse("2006/01/02/15", extractDateFromFolder.FindString(pathX))
			if err != nil {
				fmt.Println("Error-current_data_time_window_function:", err)
				return errors.New("STOP")
			}
			prometheus.Current_data_window_in_hours.Set(time.Since(myDate).Hours())
			return errors.New("STOP")
		}
	}

	return nil
}

var autoCleanFunction = func(pathX string, infoX os.DirEntry, errX error) error {
	usageStat, err := disk.UsageWithContext(ctx, config.Settings.Get(config.DATA_FOLDER))
	if err != nil {
		fmt.Println("Panic! Disk usage not working err:", err)
		return filepath.SkipDir
	}

	if usageStat.UsedPercent < DiskUsageAllowed {
		return filepath.SkipDir
	}

	if errX != nil {
		fmt.Printf("autoCleanFunction: error 「%v」 at a path 「%q」\n", errX, pathX)
		return errX
	}

	if !infoX.IsDir() {
		if filepath.Ext(pathX) == ".tar" {
			fileLock := flock.New(pathX)
			locked, err := fileLock.TryLockContext(ctx, 500*time.Millisecond)
			if err != nil {
				fmt.Println("lock timeout:", err)
				return filepath.SkipDir
			}
			if !locked {
				fmt.Println("file not locked:")
				return filepath.SkipDir
			}
			defer fileLock.Unlock()

			err = os.Remove(pathX)
			fmt.Printf("AutoDelete: %v DeleteWhen: %v<%v\r\n", pathX, usageStat.UsedPercent, DiskUsageAllowed)
			if err != nil {
				fmt.Println("Remove file error: ", err)
			}

		}
	}

	return nil
}

func AutoClean() {
	fmt.Println("AutoClean start")
	for {
		filepath.WalkDir(config.Settings.Get(config.DATA_FOLDER), current_data_time_window_function)
		time.Sleep(10000 * time.Millisecond)
		usageStat, err := disk.UsageWithContext(ctx, config.Settings.Get(config.DATA_FOLDER))
		if err != nil {
			fmt.Println("Panic! Disk usage not working err:", err)
		}

		if usageStat.UsedPercent > DiskUsageAllowed {
			fmt.Println("Start autoClean:", usageStat.UsedPercent)
			fmt.Printf("Start AutoClean DeleteWhen: %v<%v\r\n", usageStat.UsedPercent, DiskUsageAllowed)
			err := filepath.WalkDir(config.Settings.Get(config.DATA_FOLDER), autoCleanFunction)

			if err != nil {
				fmt.Printf("error walking the path %q: %v\n", config.Settings.Get(config.DATA_FOLDER), err)
			}
		}

	}

}

