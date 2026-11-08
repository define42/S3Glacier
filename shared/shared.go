package shared

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"glacier/archive"
	"glacier/bucket"
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
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/linkedin/goavro"
)

// ExtractGUID matches lowercase, hyphenated UUID substrings, including UUIDs
// embedded in filenames. It does not validate the UUID version or timestamp.
func ExtractGUID() *regexp.Regexp {
	r, err := regexp.Compile("([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})")
	if err != nil {
		panic(err)
	}
	return r
}

var extractGUID = ExtractGUID()

// GetBucketContainerFile returns the archive path and first UUID substring in
// uuidString without creating files. It accepts only timestamped UUIDv4 values
// whose first two groups encode YYYYMMDD-HHMM with a year from 2000 through 2099.
// Only the date and hour determine the folder; ordinary minutes are ignored.
//
// When EXTEND_LIFE_SUPPORT is exactly "true", the last two characters of the
// second group are interpreted as a hexadecimal byte. A set high bit adds the
// remaining seven bits as calendar months using [time.Time.AddDate].
// Changing this setting can change where an existing flagged UUID is found.
//
// The path is b.Path/YYYY/MM/DD/HH/shard.tar, with a four-digit hexadecimal shard
// from SHA-256(UUID bytes), first eight bytes in big-endian order, modulo the
// fixed bucket count. Invalid counts return bucket.ErrInvalidTarFiles; invalid
// UUIDs, unsupported versions, and invalid v4 dates or hours return errors.
func GetBucketContainerFile(b bucket.Bucket, uuidString string) (string, string, error) {
	if b.TarFilesPerHour < 1 || b.TarFilesPerHour > bucket.MaxTarFilesPerHour {
		return "", "", bucket.ErrInvalidTarFiles
	}
	timeUuid := extractGUID.FindString(uuidString)
	id, err := uuid.Parse(timeUuid)
	if err != nil {
		return "", timeUuid, err
	}
	if id.Version() != 4 || timeUuid[:2] != "20" {
		return "", timeUuid, errors.New("UUID must be a timestamped version 4")
	}
	timestamp, err := time.Parse("2006010215", timeUuid[:8]+timeUuid[9:11])
	if err != nil {
		return "", timeUuid, fmt.Errorf("invalid UUID timestamp: %w", err)
	}
	keep, _ := strconv.ParseUint(timeUuid[11:13], 16, 8)
	if config.Settings.Get(config.EXTEND_LIFE_SUPPORT) == "true" && keep&0x80 != 0 {
		timestamp = timestamp.AddDate(0, int(keep&0x7f), 0)
	}
	hash := sha256.Sum256(id[:])
	index := binary.BigEndian.Uint64(hash[:8]) % uint64(b.TarFilesPerHour)
	shard := fmt.Sprintf("%04x", index)
	return filepath.Join(b.Path, timestamp.Format("2006/01/02/15"), shard+".tar"), timeUuid, nil
}

// GetFileTime supplies the S3 Last-Modified value: UTC midnight of a timestamped
// UUIDv4's date, or the current time for unsupported or invalid inputs. It ignores
// the hour and EXTEND_LIFE_SUPPORT and must not be used to locate stored objects.
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

func outputAvro2Json(reader io.Reader, w http.ResponseWriter) (bool, error) {

	// Create a new OCF Reader
	avroReader, err := goavro.NewOCFReader(reader)
	if err != nil {
		return false, err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Iterate through all Avro data records
	w.Write([]byte("["))
	for avroReader.Scan() {
		// Get the next Avro data record
		nativeData, err := avroReader.Read()
		if err != nil {
			return true, err
		}

		// Convert native data to JSON
		jsonData, err := json.Marshal(nativeData)
		if err != nil {
			return true, err
		}
		_, err = w.Write(jsonData)
		if err != nil {
			return true, err
		}
		if avroReader.RemainingBlockItems() > 0 {
			_, err = w.Write([]byte(","))
			if err != nil {
				return true, err
			}
		}

	}
	w.Write([]byte("]"))

	return true, nil
}

// GetBucketFile serves the first matching UUID entry after the caller authorizes
// bucket access. The object ID comes from the mux "id" variable. HEAD returns
// object headers; ?parse=avro requests an Avro-to-JSON view.
//
// Reads use the archive manager's committed view and shared lock, with
// acquisition controlled by r.Context(). Missing objects return 404, invalid IDs
// return 400, busy or quarantined archives return 503, and corruption or decoding
// failures return 500 when headers are not yet written.
func GetBucketFile(w http.ResponseWriter, r *http.Request, b bucket.Bucket) {
	id := mux.Vars(r)["id"]
	containerFile, id, err := GetBucketContainerFile(b, id)
	if err != nil {
		objectReadError(w, err.Error(), http.StatusBadRequest)
		return
	}
	tarFile, err := archive.Default.Open(r.Context(), containerFile)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			objectReadError(w, "File not found", http.StatusNotFound)
		case errors.Is(err, archive.ErrBusy):
			w.Header().Set("Retry-After", "1")
			objectReadError(w, "Archive is busy; try again", http.StatusServiceUnavailable)
		case errors.Is(err, archive.ErrUnavailable):
			objectReadError(w, "Archive is unavailable", http.StatusServiceUnavailable)
		default:
			objectReadError(w, "Unable to open archive", http.StatusInternalServerError)
		}
		return
	}
	defer tarFile.Close()

	tr := tar.NewReader(tarFile)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			objectReadError(w, "File not found", http.StatusNotFound)
			return
		}
		if err != nil {
			objectReadError(w, "Unable to read archive", http.StatusInternalServerError)
			return
		}
		if !archive.IsInternalEntry(hdr) && id == hdr.Name {
			serveBucketEntry(w, r, hdr, tr)
			return
		}
	}
}

func objectReadError(w http.ResponseWriter, message string, status int) {
	ClearObjectMetadataHeaders(w.Header())
	http.Error(w, message, status)
}

func serveBucketEntry(w http.ResponseWriter, r *http.Request, header *tar.Header, stored io.Reader) {
	metadata, err := ObjectMetadataFromTar(header)
	if err != nil || !validMetadataValue(header.Gname) {
		objectReadError(w, "Invalid stored object metadata", http.StatusInternalServerError)
		return
	}
	transformed := r.URL.Query().Get("parse") == "avro"
	if transformed {
		ClearObjectMetadataHeaders(w.Header())
		w.Header().Set("Content-Type", "application/json")
	} else {
		applyObjectMetadata(w.Header(), metadata, header.Gname)
		size := header.Size
		if header.Mode == 1 {
			size = int64(header.Uid)
		}
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if header.Mode == 1 {
		reader, err := gzip.NewReader(stored)
		if err != nil {
			objectReadError(w, "Unable to decompress object", http.StatusInternalServerError)
			return
		}
		defer reader.Close()
		stored = reader
	}
	if transformed {
		started, err := outputAvro2Json(stored, w)
		if err != nil {
			if !started {
				objectReadError(w, "Unable to decode Avro object", http.StatusInternalServerError)
			} else {
				fmt.Println("stream Avro object:", err)
			}
		}
		return
	}
	if written, err := io.Copy(w, stored); err != nil {
		if written == 0 {
			objectReadError(w, "Unable to read object", http.StatusInternalServerError)
		} else {
			fmt.Println("stream object:", err)
		}
	}
}

// UploadToBucket commits a complete, in-memory object after the caller authorizes
// bucket access. It returns the normalized UUID and archive path. Every
// successful upload appends an entry, including repeated UUIDs with identical or
// different bytes. GetBucketFile continues to return the first committed match.
// The request context controls lock acquisition, and archive errors propagate
// to the HTTP/S3 caller.
// Compression may allocate another full buffer in addition to fileBytes.
func UploadToBucket(r *http.Request, b bucket.Bucket, id string, fileBytes []byte) (string, string, error) {
	return UploadToBucketWithMetadata(r, b, id, fileBytes, ObjectMetadata{})
}

// UploadToBucketWithMetadata commits explicit object metadata in the same TAR
// entry as its payload. It does not infer object properties from HTTP transport
// headers. Invalid metadata is rejected before compression or archive writes.
func UploadToBucketWithMetadata(r *http.Request, b bucket.Bucket, id string, fileBytes []byte, metadata ObjectMetadata) (string, string, error) {
	metadata, err := normalizeObjectMetadata(metadata)
	if err != nil {
		return "", "", err
	}
	containerFile, uuid_id, err := GetBucketContainerFile(b, id)
	if err != nil {
		fmt.Println(err)
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

	storedPayload := fileBytes
	header := &tar.Header{
		Name: uuid_id, Size: int64(len(fileBytes)), Format: tar.FormatPAX,
		Uname: id, PAXRecords: metadata.paxRecords(), Gname: mtype.String(),
	}
	if contentType := metadata.Headers["content-type"]; contentType != "" {
		header.Gname = contentType
	}
	if doCompress {
		storedPayload = output.Bytes()
		header.Size = int64(len(storedPayload))
		header.Uid = len(fileBytes)
		header.Mode = 1
	}
	prometheus.Tar_files_open.Inc()
	defer prometheus.Tar_files_open.Dec()
	appended, err := archive.Default.Append(r.Context(), containerFile, header, storedPayload, sha256.Sum256(fileBytes))
	if err != nil {
		return "", "", err
	}
	if appended {
		prometheus.RawUploadDoneProcessed.Inc()
	}
	return uuid_id, containerFile, nil
}

// GenerateTimeUUID replaces a random UUIDv4's first two groups with the process's
// local date and minute (YYYYMMDD-HHMM). These ordinary minute values never set
// the hexadecimal high bit used by EXTEND_LIFE_SUPPORT.
func GenerateTimeUUID() string {
	id, _ := uuid.NewRandom()
	timeStamp := time.Now()
	idString := timeStamp.Format("20060102-1504") + id.String()[13:]
	return idString
}
