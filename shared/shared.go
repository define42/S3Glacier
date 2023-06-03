package shared

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"glacier/config"
	"glacier/prometheus"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/gofrs/flock"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/linkedin/goavro"
)

var ctx = context.Background()

func ExtractGUID() *regexp.Regexp {
	r, err := regexp.Compile("([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})")
	if err != nil {
		panic(err)
	}
	return r
}

var extractGUID = ExtractGUID()

func GetContainerFile(uuidString string) (string, string, error) {
	timeUuid := extractGUID.FindString(uuidString)
	id, err := uuid.Parse(timeUuid)

	if err != nil {
		return "", timeUuid, err
	}
	if id.Version() == 1 {
		sec, nsec := id.Time().UnixTime()
		timestamp := time.Unix(sec, nsec).UTC()

		idString := timestamp.Format("200601021504")
		return "files/" + idString[0:4] + "/" + idString[4:6] + "/" + idString[6:8] + "/" + idString[8:10] + "/" + timeUuid[4:6] + ".tar", timeUuid, err
	}

	if id.Version() != 4 {
		return "", timeUuid, errors.New("UUID not version 4")
	}
	if timeUuid[0:2] != "20" {
		return "", timeUuid, errors.New("UUID not time-uuid")
	}

	keep, err := strconv.ParseUint(timeUuid[11:13], 16, 64)
	if err != nil {
		keep = 0
		fmt.Println("strconv.ParseUint:", err)
	}
	//fmt.Println("uint8:", uint8(keep))
	if config.Settings.Get(config.EXTEND_LIFE_SUPPORT) == "true" && uint8(keep)&0x80 == 0x80 {
		keep = uint64(uint8(keep) & 0x7f)
		TimeLayout := "20060102"
		timestamp, err := time.Parse(TimeLayout, timeUuid[0:8])
		if err != nil {
			return "", timeUuid, errors.New("UUID unable to pase timeUuid:" + timeUuid)
		}
		//fmt.Println(timestamp)
		timestamp = timestamp.AddDate(0, int(keep), 0)
		idString := timestamp.Format("20060102")
		//fmt.Println(timestamp)
		return "files/" + idString[0:4] + "/" + idString[4:6] + "/" + idString[6:8] + "/" + timeUuid[9:11] + "/" + timeUuid[34:36] + ".tar", timeUuid, err
	} else {
		return "files/" + timeUuid[0:4] + "/" + timeUuid[4:6] + "/" + timeUuid[6:8] + "/" + timeUuid[9:11] + "/" + timeUuid[34:36] + ".tar", timeUuid, err
	}

}

func GetFileTime(uuidString string) time.Time {
	timeUuid := extractGUID.FindString(uuidString)
	id, err := uuid.Parse(timeUuid)

	if err != nil {
		return time.Now()
	}

	if id.Version() != 4 {
		return time.Now()
	}
	if timeUuid[0:2] != "20" {
		return time.Now()
	}

	TimeLayout := "20060102"
	timestamp, err := time.Parse(TimeLayout, timeUuid[0:8])
	if err != nil {
		return time.Now()
	}
	return timestamp
}

func outputAvro2Json(reader io.Reader, w http.ResponseWriter) error {

	// Create a new OCF Reader
	avroReader, err := goavro.NewOCFReader(reader)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Iterate through all Avro data records
	w.Write([]byte("["))
	for avroReader.Scan() {
		// Get the next Avro data record
		nativeData, err := avroReader.Read()
		if err != nil {
			return err
		}

		// Convert native data to JSON
		jsonData, err := json.Marshal(nativeData)
		if err != nil {
			return err
		}
		_, err = w.Write(jsonData)
		if err != nil {
			return err
		}
		if avroReader.RemainingBlockItems() > 0 {
			_, err = w.Write([]byte(","))
			if err != nil {
				return err
			}
		}

	}
	w.Write([]byte("]"))

	return nil
}

func GetFile(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	vars := mux.Vars(r)
	id, ok := vars["id"]
	if !ok {
		fmt.Println("id is missing in parameters")
	}
	fmt.Println(id)
	token, ok := vars["token"]
	if !ok {
		fmt.Println("token is missing in parameters")
	}
	query := r.URL.Query()

	// Access individual query parameters
	parse := query.Get("parse")
	fmt.Println(parse)

	fmt.Println(token)
	if config.Settings.Has(config.READ_TOKEN) && token != config.Settings.Get(config.READ_TOKEN) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Access forbidden")
		return
	}

	containerFile, id, err := GetContainerFile(id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, err)
		fmt.Println(err)
		return
	}
	fileLock := flock.New(containerFile)
	locked, err := fileLock.TryLockContext(ctx, 500*time.Millisecond)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, err)
		fmt.Println("lock timeout:", err)
		return
	}
	if !locked {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println("file not locked:")
		return
	}
	defer fileLock.Unlock()
	tarFile, err := os.Open(containerFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "open tar file failed", err)
		return
	}
	defer tarFile.Close()

	tr := tar.NewReader(tarFile)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, "File not found")
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "open tar file failed", err)
			return
		}
		if id == hdr.Name {
			if len(hdr.Gname) > 0 {
				w.Header().Set("Content-Type", hdr.Gname)
			}
			if hdr.Mode == int64(1) {
				gzf, err := gzip.NewReader(tr)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintln(w, "gzip decompress error:", err)
					return
				}
				defer gzf.Close()

				if parse == "avro" {
					err = outputAvro2Json(gzf, w)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						fmt.Fprintln(w, "avro to json error:", err)
					}
					return
				}

				_, err = io.Copy(w, gzf)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintln(w, "open compressed tar file failed", err)
					fmt.Println("open compressed file failed", err)
					return
				}
			} else {
				if parse == "avro" {
					err = outputAvro2Json(tr, w)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						fmt.Fprintln(w, "avro to json error:", err)
					}
					return
				}
				if _, err := io.Copy(w, tr); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintln(w, "open tar file failed", err)
					return
				}
			}
			return
		}
	}
}

func SharedUpload(r *http.Request, token string, id string, fileBytes []byte) (string, string, error) {

	if config.Settings.Has(config.WRITE_TOKEN) && token != config.Settings.Get(config.WRITE_TOKEN) {

		return "", "", fmt.Errorf("Access denied")
	}

	containerFile, uuid_id, err := GetContainerFile(id)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	containerPath := filepath.Dir(containerFile)

	err = os.MkdirAll(containerPath, 0700)

	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	if len(fileBytes) == 0 {
		fmt.Println("FileSize==0")
		return "", "", err
	}
	mtype := mimetype.Detect(fileBytes)
	doCompress := false
	if len(fileBytes) > 100 { // Pointless compressing small blobs as GZIP-header will create big overhead
		_, doCompress = DO_COMPRESS[mtype.Extension()]
		if !doCompress {
			_, doCompress = DO_COMPRESS[mtype.String()]
		}
	}
	if len(fileBytes) < 20000000 && len(fileBytes) > 100 {
		doCompress = true
	}

	var output bytes.Buffer
	if doCompress { // Compress content
		gw := gzip.NewWriter(&output)

		_, err = gw.Write(fileBytes)
		if err != nil {
			return "", "", err
		}
		if err := gw.Close(); err != nil {
			return "", "", err
		}
	}

	fileLock := flock.New(containerFile)
	locked, err := fileLock.TryLockContext(ctx, 500*time.Millisecond)
	if err != nil {
		fmt.Println("lock timeout:", err)
		return "", "", err
	}
	if !locked {
		fmt.Println("file not locked:")
		return "", "", err
	}
	defer fileLock.Unlock()

	prometheus.Tar_files_open.Inc()
	defer prometheus.Tar_files_open.Dec()

	f, err := os.OpenFile(containerFile, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", "", err
	}
	if fi.Size() > 0 {
		if _, err = f.Seek(-2<<9, os.SEEK_END); err != nil {
			fmt.Println(err)
		}
	}

	tw := tar.NewWriter(f)

	metadata := make(map[string]string)

	//metadata["test"] = "test"
	if !doCompress {
		hdr := &tar.Header{
			Name:       uuid_id,
			Size:       int64(len(fileBytes)),
			Format:     tar.FormatPAX,
			Uname:      id,
			PAXRecords: metadata,
			Gname:      mtype.String(),
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return "", "", err
		}

		if _, err := tw.Write(fileBytes); err != nil {
			return "", "", err
		}
	} else {
		hdr := &tar.Header{
			Name:       uuid_id,
			Size:       int64(output.Len()),
			Uid:        int(len(fileBytes)),
			Format:     tar.FormatPAX,
			Uname:      id,
			Gname:      mtype.String(),
			PAXRecords: metadata,
			Mode:       1, //Define we use compression
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return "", "", err
		}
		if _, err := io.Copy(tw, &output); err != nil {
			return "", "", err
		}
	}

	if err := tw.Close(); err != nil {
		return "", "", err
	}
	prometheus.RawUploadDoneProcessed.Inc()
	//	fmt.Fprintf(w, "<html><a href=get/%v>%v</a> <br><a href=%v>%v</a>", id, id, containerFile, containerFile)
	return id, containerFile, nil
}

func GenerateTimeUUID() string {
	id, _ := uuid.NewRandom()
	timeStamp := time.Now()
	idString := timeStamp.Format("20060102-1504") + id.String()[13:]
	return idString
}
