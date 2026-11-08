package shared_test

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"glacier/archive"
	"glacier/bucket"
	"glacier/shared"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/linkedin/goavro"
)

func TestParseObjectMetadataNormalizesAllowedHeaders(t *testing.T) {
	t.Parallel()
	headers := http.Header{
		"X-Amz-Meta-Owner": {"first", "second"}, "x-amz-meta-owner": {"third"},
		"X-Amz-Meta-Label": {mime.BEncoding.Encode("UTF-8", "café")},
		"X-Amz-Meta-Empty": {""}, "X-Amz-Meta-sha256": {"custom checksum label"},
		"Content-Type": {"application/custom"}, "Content-Disposition": {`attachment; filename="report.txt"`},
		"Content-Encoding": {"gzip", "br"}, "Content-Language": {"en", "da"},
		"Cache-Control": {"private", "max-age=60"}, "Expires": {"Wed, 21 Oct 2030 07:28:00 GMT"},
		"Authorization": {"must not persist"}, "Content-Length": {"999"}, "ETag": {"client-etag"},
		"X-Amz-Security-Token": {"must not persist"}, "X-Amz-Acl": {"public-read"},
	}
	before := headers.Clone()
	got, err := shared.ParseObjectMetadata(headers)
	if err != nil {
		t.Fatal(err)
	}
	wantUser := map[string]string{"owner": "first,second,third", "label": "café", "empty": "", "sha256": "custom checksum label"}
	wantHeaders := map[string]string{
		"content-type": "application/custom", "content-disposition": `attachment; filename="report.txt"`,
		"content-encoding": "gzip,br", "content-language": "en,da", "cache-control": "private,max-age=60",
		"expires": "Wed, 21 Oct 2030 07:28:00 GMT",
	}
	if !maps.Equal(got.User, wantUser) || !maps.Equal(got.Headers, wantHeaders) || got.ETag != "" {
		t.Fatalf("metadata = %#v", got)
	}
	for name, values := range before {
		if strings.Join(values, "\x00") != strings.Join(headers[name], "\x00") {
			t.Fatal("ParseObjectMetadata mutated the caller's headers")
		}
	}
}

func TestParseObjectMetadataRejectsInvalidFields(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		header http.Header
	}{
		{"empty key", http.Header{"X-Amz-Meta-": {"value"}}},
		{"invalid key", http.Header{"X-Amz-Meta-a=b": {"value"}}},
		{"non ASCII key", http.Header{"X-Amz-Meta-K": {"value"}}},
		{"header injection", http.Header{"X-Amz-Meta-name": {"safe\r\nInjected: true"}}},
		{"nul value", http.Header{"X-Amz-Meta-name": {"bad\x00value"}}},
		{"invalid UTF8", http.Header{"X-Amz-Meta-name": {"bad\xffvalue"}}},
		{"encoded control", http.Header{"X-Amz-Meta-name": {"=?UTF-8?B?DQo=?="}}},
		{"singleton repeat", http.Header{"Content-Type": {"text/plain", "application/json"}}},
		{"singleton case variant", http.Header{"Content-Type": {"text/plain"}, "content-type": {"text/plain"}}},
		{"invalid representation", http.Header{"Content-Disposition": {"attachment\nInjected: true"}}},
		{"wire encoding", http.Header{"Content-Encoding": {"gzip, AWS-CHUNKED"}}},
		{"invalid encoding", http.Header{"Content-Encoding": {"gzip;invalid"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := shared.ParseObjectMetadata(test.header); !errors.Is(err, archive.ErrInvalidEntry) {
				t.Fatalf("ParseObjectMetadata error = %v, want invalid metadata", err)
			}
		})
	}
}

func TestParseObjectMetadataEnforcesSeparateByteBudgets(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		header http.Header
		tooBig bool
	}{
		{"user boundary", http.Header{"X-Amz-Meta-a": {strings.Repeat("x", 2047)}}, false},
		{"user overflow", http.Header{"X-Amz-Meta-a": {strings.Repeat("x", 2048)}}, true},
		{"Unicode bytes", http.Header{"X-Amz-Meta-a": {strings.Repeat("é", 1024)}}, true},
		{"duplicate comma boundary", http.Header{"X-Amz-Meta-a": {strings.Repeat("x", 1023), strings.Repeat("x", 1023)}}, false},
		{"duplicate comma overflow", http.Header{"X-Amz-Meta-a": {strings.Repeat("x", 1024), strings.Repeat("x", 1023)}}, true},
		{"representation boundary", http.Header{"Cache-Control": {strings.Repeat("x", 2048-len("cache-control"))}}, false},
		{"representation overflow", http.Header{"Cache-Control": {strings.Repeat("x", 2049-len("cache-control"))}}, true},
		{"independent budgets", http.Header{"X-Amz-Meta-a": {strings.Repeat("x", 2047)}, "Cache-Control": {strings.Repeat("x", 2048-len("cache-control"))}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := shared.ParseObjectMetadata(test.header)
			if test.tooBig {
				if !errors.Is(err, shared.ErrMetadataTooLarge) || !errors.Is(err, archive.ErrInvalidEntry) {
					t.Fatalf("size error = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestObjectMetadataRoundTripsPAXAndFirstEntry(t *testing.T) {
	root := configureStorage(t)
	b, err := openBuckets(t, root).Create("object-metadata", 1)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("object body\n"), 100)
	digest := md5.Sum(data)
	metadata := shared.ObjectMetadata{
		User:    map[string]string{"Owner": "first", "filename": "report.txt", "sha256": "user value", "http.content-type": "also user metadata", "label": "café"},
		Headers: map[string]string{"Content-Type": "application/custom", "content-disposition": `attachment; filename="report.txt"`, "content-language": "en", "cache-control": "private", "expires": "Wed, 21 Oct 2030 07:28:00 GMT"},
		ETag:    hex.EncodeToString(digest[:]),
	}
	request := httptest.NewRequest(http.MethodPut, "/", nil)
	_, path, err := shared.UploadToBucketWithMetadata(request, b, v4ID, data, metadata)
	if err != nil {
		t.Fatal(err)
	}
	header := metadataFirstHeader(t, path)
	originalDigest := sha256.Sum256(data)
	for name, want := range map[string]string{
		shared.PAXUserMetadataPrefix + "owner": "first", shared.PAXUserMetadataPrefix + "filename": "report.txt",
		shared.PAXUserMetadataPrefix + "sha256": "user value", shared.PAXUserMetadataPrefix + "http.content-type": "also user metadata",
		shared.PAXHTTPMetadataPrefix + "content-type": "application/custom", shared.PAXETagKey: metadata.ETag,
		archive.SHA256Key: hex.EncodeToString(originalDigest[:]),
	} {
		if header.PAXRecords[name] != want {
			t.Errorf("PAX[%q]=%q, want %q", name, header.PAXRecords[name], want)
		}
	}
	if _, exists := header.PAXRecords["S3Glacier.s3"]; exists {
		t.Fatal("metadata was stored in a JSON envelope")
	}
	if header.Mode != 1 || header.Uid != len(data) || header.Gname != "application/custom" {
		t.Fatalf("storage metadata changed: mode=%d size=%d contentType=%q", header.Mode, header.Uid, header.Gname)
	}
	decoded, err := shared.ObjectMetadataFromTar(header)
	if err != nil || decoded.User["owner"] != "first" || decoded.ETag != metadata.ETag {
		t.Fatalf("PAX metadata = %#v, %v", decoded, err)
	}
	later := shared.ObjectMetadata{User: map[string]string{"owner": "later"}, Headers: map[string]string{"content-type": "text/later"}, ETag: strings.Repeat("1", 32)}
	if _, _, err := shared.UploadToBucketWithMetadata(request, b, v4ID, []byte("later payload"), later); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := metadataResponse(b, v4ID, method, "")
		if response.Code != http.StatusOK || response.Header().Get("ETag") != `"`+metadata.ETag+`"` || response.Header().Get("Content-Type") != "application/custom" || response.Header().Get("X-Amz-Meta-Owner") != "first" {
			t.Fatalf("%s first metadata: status=%d headers=%v", method, response.Code, response.Header())
		}
		if response.Header().Get("Content-Encoding") != "" || response.Header().Get("Content-Length") != strconv.Itoa(len(data)) {
			t.Fatalf("internal gzip escaped in %s headers: %v", method, response.Header())
		}
		label, err := new(mime.WordDecoder).DecodeHeader(response.Header().Get("X-Amz-Meta-Label"))
		if err != nil || label != "café" {
			t.Fatalf("Unicode metadata = %q, %v", label, err)
		}
		if method == http.MethodGet && !bytes.Equal(response.Body.Bytes(), data) || method == http.MethodHead && response.Body.Len() != 0 {
			t.Fatalf("%s returned the wrong payload", method)
		}
	}
}

func TestObjectMetadataEncodedWordsDecodeExactlyOnce(t *testing.T) {
	root := configureStorage(t)
	b, err := openBuckets(t, root).Create("encoded-metadata", 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, value := range []string{"=?UTF-8?B?aGVsbG8=?=", strings.Repeat("=?UTF-8?Q?hello?= ", 7), " keep these spaces ", "文字 café"} {
		wire := "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(value)) + "?="
		metadata, err := shared.ParseObjectMetadata(http.Header{"X-Amz-Meta-Literal": {wire}})
		if err != nil || metadata.User["literal"] != value {
			t.Fatalf("initial wire decoding: metadata=%v err=%v", metadata, err)
		}
		id := "20261107-1036-4000-8000-00000000000" + strconv.Itoa(i)
		_, path, err := shared.UploadToBucketWithMetadata(httptest.NewRequest(http.MethodPut, "/", nil), b, id, []byte("body"), metadata)
		if err != nil {
			t.Fatal(err)
		}
		// All objects share one shard; locate this exact object's direct PAX value.
		header := metadataNamedHeader(t, path, id)
		if header.PAXRecords[shared.PAXUserMetadataPrefix+"literal"] != value {
			t.Fatalf("stored literal changed: %q", header.PAXRecords[shared.PAXUserMetadataPrefix+"literal"])
		}
		for range 2 {
			decoded, err := shared.ObjectMetadataFromTar(header)
			if err != nil || decoded.User["literal"] != value {
				t.Fatalf("repeated PAX decode changed value: %q, %v", decoded.User["literal"], err)
			}
		}
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			response := metadataResponse(b, id, method, "")
			got, err := new(mime.WordDecoder).DecodeHeader(response.Header().Get("X-Amz-Meta-Literal"))
			if response.Code != http.StatusOK || err != nil || got != value {
				t.Fatalf("%s literal roundtrip: status=%d got=%q want=%q err=%v", method, response.Code, got, value, err)
			}
		}
	}
}

func TestInvalidObjectMetadataDoesNotChangeOrQuarantineArchive(t *testing.T) {
	root := configureStorage(t)
	b, err := openBuckets(t, root).Create("invalid-metadata", 1)
	if err != nil {
		t.Fatal(err)
	}
	path := uploadObject(t, b, v4ID, []byte("first"))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, metadata := range []shared.ObjectMetadata{
		{User: map[string]string{"bad=name": "value"}},
		{User: map[string]string{"name": "value\r\nInjected: header"}},
		{User: map[string]string{"name": strings.Repeat("x", 2048)}},
		{Headers: map[string]string{"authorization": "must not persist"}},
		{Headers: map[string]string{"content-encoding": "aws-chunked"}},
		{ETag: strings.Repeat("A", 32)},
	} {
		_, _, err := shared.UploadToBucketWithMetadata(httptest.NewRequest(http.MethodPut, "/", nil), b, v4ID, []byte("bad append"), metadata)
		if !errors.Is(err, archive.ErrInvalidEntry) {
			t.Fatalf("invalid upload error = %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("invalid metadata changed TAR: %v", err)
		}
	}
	newID := "20261107-1036-4000-8000-000000000099"
	uploadObject(t, b, newID, []byte("still healthy"))
	if response := getObject(b, newID); response.Code != http.StatusOK || response.Body.String() != "still healthy" {
		t.Fatalf("valid upload after rejection: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestObjectMetadataLegacyWrapperIgnoresTransportHeaders(t *testing.T) {
	root := configureStorage(t)
	b, err := openBuckets(t, root).Create("legacy-metadata", 1)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Content-Type", "multipart/form-data; boundary=transport-only")
	request.Header.Set("Content-Encoding", "gzip")
	request.Header.Set("X-Amz-Meta-Owner", "not an S3 upload")
	_, path, err := shared.UploadToBucket(request, b, v4ID, []byte("plain object"))
	if err != nil {
		t.Fatal(err)
	}
	header := metadataFirstHeader(t, path)
	metadata, err := shared.ObjectMetadataFromTar(header)
	if err != nil || len(metadata.User) != 0 || len(metadata.Headers) != 0 || metadata.ETag != "" {
		t.Fatalf("legacy upload persisted transport headers: metadata=%v err=%v", metadata, err)
	}
	response := getObject(b, v4ID)
	if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/plain") || response.Header().Get("Content-Encoding") != "" {
		t.Fatalf("legacy content-type fallback changed: status=%d headers=%v", response.Code, response.Header())
	}
}

func TestObjectMetadataAvroViewAndErrorsClearRepresentationHeaders(t *testing.T) {
	root := configureStorage(t)
	b, err := openBuckets(t, root).Create("metadata-views", 1)
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	writer, err := goavro.NewOCFWriter(goavro.OCFConfig{W: &data, Schema: `{"type":"record","name":"Message","fields":[{"name":"message","type":"string"}]}`})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Append([]any{map[string]any{"message": "hello"}}); err != nil {
		t.Fatal(err)
	}
	metadata := shared.ObjectMetadata{
		User: map[string]string{"owner": "object"}, ETag: strings.Repeat("1", 32),
		Headers: map[string]string{"content-type": "application/avro", "content-encoding": "identity", "content-disposition": "attachment", "cache-control": "private"},
	}
	if _, _, err := shared.UploadToBucketWithMetadata(httptest.NewRequest(http.MethodPut, "/", nil), b, v4ID, data.Bytes(), metadata); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := metadataResponse(b, v4ID, method, "?parse=avro")
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s Avro view: status=%d headers=%v body=%q", method, response.Code, response.Header(), response.Body.String())
		}
		for _, name := range []string{"Content-Encoding", "Content-Disposition", "Content-Length", "ETag", "X-Amz-Meta-Owner"} {
			if response.Header().Get(name) != "" {
				t.Fatalf("Avro view reused %s: %q", name, response.Header().Get(name))
			}
		}
		if method == http.MethodGet {
			var rows []map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &rows); err != nil || len(rows) != 1 || rows[0]["message"] != "hello" {
				t.Fatalf("invalid Avro JSON: %q, %v", response.Body.String(), err)
			}
		}
	}
	badID := "20261107-1036-4000-8000-000000000098"
	path, _, err := shared.GetBucketContainerFile(b, badID)
	if err != nil {
		t.Fatal(err)
	}
	bad := []byte("not gzip")
	header := &tar.Header{Name: badID, Typeflag: tar.TypeReg, Size: int64(len(bad)), Mode: 1, Uid: 100, Gname: "application/original", PAXRecords: map[string]string{
		shared.PAXHTTPMetadataPrefix + "content-encoding": "gzip", shared.PAXHTTPMetadataPrefix + "content-disposition": "attachment", shared.PAXETagKey: strings.Repeat("2", 32), shared.PAXUserMetadataPrefix + "owner": "hidden",
	}}
	if _, err := archive.Default.Append(t.Context(), path, header, bad, sha256.Sum256(bad)); err != nil {
		t.Fatal(err)
	}
	response := getObject(b, badID)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("bad gzip status=%d", response.Code)
	}
	for _, name := range []string{"Content-Encoding", "Content-Disposition", "Content-Length", "ETag", "X-Amz-Meta-Owner"} {
		if response.Header().Get(name) != "" {
			t.Fatalf("error reused object %s: %q", name, response.Header().Get(name))
		}
	}
}

func metadataFirstHeader(t *testing.T, path string) *tar.Header {
	t.Helper()
	return metadataNamedHeader(t, path, "")
}

func metadataNamedHeader(t *testing.T, path, name string) *tar.Header {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if err != nil {
			t.Fatal(err)
		}
		if archive.IsInternalEntry(header) {
			continue
		}
		if name == "" || header.Name == name {
			return header
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			t.Fatal(err)
		}
	}
}

func metadataResponse(b bucket.Bucket, id, method, query string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/"+b.Name+"/"+id+query, nil)
	request = mux.SetURLVars(request, map[string]string{"id": id})
	response := httptest.NewRecorder()
	shared.GetBucketFile(response, request, b)
	return response
}
