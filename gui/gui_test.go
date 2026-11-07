package gui

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/json"
	"glacier/archive"
	"glacier/bucket"
	"glacier/config"
	"glacier/shared"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

func TestFileViewRequiresReadToken(t *testing.T) {
	store, _ := testStore(t)
	t.Setenv(config.READ_TOKEN, "read-secret")
	config.Settings.Set(config.READ_TOKEN, "", "")
	request := httptest.NewRequest(http.MethodGet, "/files/", nil)
	response := httptest.NewRecorder()
	FileView(store).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated browse status = %d", response.Code)
	}
}

func TestFileViewIsolatesBucketTrees(t *testing.T) {
	store, data := testStore(t)
	logs, err := store.Create("logs", 4)
	if err != nil {
		t.Fatal(err)
	}
	writeGUIArchive(t, data.Path, "2026/11/07/10/0000.tar", "data")
	writeGUIArchive(t, logs.Path, "2025/11/07/10/0000.tar", "logs")
	view := FileView(store)
	tests := []struct {
		name   string
		bucket string
		path   string
		status int
		want   string
		absent string
	}{
		{name: "default bucket root", bucket: "data", status: http.StatusOK, want: "2026", absent: "2025"},
		{name: "new bucket root", bucket: "logs", status: http.StatusOK, want: "2025", absent: "2026"},
		{name: "metadata blocked", bucket: "data", path: ".buckets/data.json", status: http.StatusNotFound},
		{name: "other bucket directory blocked", bucket: "data", path: "buckets/logs/2025/11/07/10/0000.tar", status: http.StatusNotFound},
		{name: "traversal blocked", bucket: "logs", path: "../data/2026/11/07/10/0000.tar", status: http.StatusNotFound},
		{name: "invalid date blocked", bucket: "logs", path: "2025/02/30/10/0000.tar", status: http.StatusNotFound},
		{name: "unknown bucket", bucket: "unknown", status: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/files/", nil)
			request = mux.SetURLVars(request, map[string]string{"bucket": tt.bucket, "path": tt.path})
			response := httptest.NewRecorder()
			view.ServeHTTP(response, request)
			if response.Code != tt.status {
				t.Fatalf("browse status = %d, want %d; body = %s", response.Code, tt.status, response.Body)
			}
			body := response.Body.String()
			if tt.want != "" && !strings.Contains(body, tt.want) {
				t.Fatalf("browse missing %q: %s", tt.want, body)
			}
			if tt.absent != "" && strings.Contains(body, tt.absent) {
				t.Fatalf("browse exposes %q: %s", tt.absent, body)
			}
			if tt.path == "" && (strings.Contains(body, ".buckets") || strings.Contains(body, ">buckets<")) {
				t.Fatalf("browse exposes internal storage entries: %s", body)
			}
		})
	}
}

func TestFileViewRejectsSymlinks(t *testing.T) {
	store, data := testStore(t)
	if err := os.Symlink("../../.buckets", filepath.Join(data.Path, "2026")); err != nil {
		t.Fatal(err)
	}
	request := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/files/2026/", nil), map[string]string{"path": "2026"})
	response := httptest.NewRecorder()
	FileView(store).ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("symlink browse status = %d", response.Code)
	}
}

func TestFileViewEscapesMetadataAndPreservesReadToken(t *testing.T) {
	store, _ := testStore(t)
	logs, err := store.Create("logs", 4)
	if err != nil {
		t.Fatal(err)
	}
	writeGUIArchive(t, logs.Path, "2026/11/07/10/0000.tar", "<script>alert(1)</script>")
	t.Setenv(config.READ_TOKEN, "read-secret")
	config.Settings.Set(config.READ_TOKEN, "", "")
	request := httptest.NewRequest(http.MethodGet, "/buckets/logs/files/2026/11/07/10/0000.tar?token=read-secret", nil)
	request = mux.SetURLVars(request, map[string]string{"bucket": "logs", "path": "2026/11/07/10/0000.tar"})
	response := httptest.NewRecorder()
	FileView(store).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("archive browse status = %d; body = %s", response.Code, response.Body)
	}
	body := response.Body.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("archive filename was not escaped: %s", body)
	}
	if strings.Contains(body, archive.ManifestName) {
		t.Fatalf("archive page exposes its internal manifest: %s", body)
	}
	if !strings.Contains(body, "/buckets/logs/get/20261107-1036-40f1-b34f-02d7517a01d3?token=read-secret") {
		t.Fatalf("archive link lost bucket or token: %s", body)
	}
	if !strings.Contains(body, "Parent folder") || !strings.Contains(body, "token=read-secret") {
		t.Fatalf("browse link lost read token: %s", body)
	}
	if strings.Contains(body, "<td>0</td>") {
		t.Fatalf("uncompressed archive reports wrong original size: %s", body)
	}
}

func TestFileViewRawDownloadRequiresReadToken(t *testing.T) {
	store, data := testStore(t)
	writeGUIArchive(t, data.Path, "2026/11/07/10/0000.tar", "data")
	t.Setenv(config.READ_TOKEN, "read-secret")
	config.Settings.Set(config.READ_TOKEN, "", "")
	request := httptest.NewRequest(http.MethodGet, "/files/2026/11/07/10/0000.tar?download=1&token=read-secret", nil)
	request = mux.SetURLVars(request, map[string]string{"path": "2026/11/07/10/0000.tar"})
	response := httptest.NewRecorder()
	FileView(store).ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/x-tar" {
		t.Fatalf("TAR download status = %d, type = %s, body = %s", response.Code, response.Header().Get("Content-Type"), response.Body)
	}
}

func TestUUIDUsesSelectedBucket(t *testing.T) {
	store, _ := testStore(t)
	logs, err := store.Create("logs", 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"v4", "v1"} {
		t.Run(name, func(t *testing.T) {
			handler := Uuidhello(store)
			if name == "v1" {
				handler = Uuidv1hello(store)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/uuid?bucket=logs", nil))
			var result MyUUID
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			wantPath, _, err := shared.GetBucketContainerFile(logs, result.Uuid)
			if err != nil || result.ContainerFile != wantPath || result.Bucket != "logs" || result.TarFilesPerHour != 4 {
				t.Fatalf("UUID result = %+v, resolved path = %s, error = %v", result, wantPath, err)
			}
		})
	}
}

func TestFileViewHidesCheckpoints(t *testing.T) {
	store, data := testStore(t)
	writeGUIArchive(t, data.Path, "2026/11/07/10/0000.tar", "data")
	view := FileView(store)
	request := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/files/2026/11/07/10/", nil), map[string]string{"path": "2026/11/07/10"})
	response := httptest.NewRecorder()
	view.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "0000.tar") || strings.Contains(response.Body.String(), "0000.commit") {
		t.Fatalf("archive directory exposes checkpoint metadata: %d %s", response.Code, response.Body)
	}
	request = mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/files/2026/11/07/10/0000.commit", nil), map[string]string{"path": "2026/11/07/10/0000.commit"})
	response = httptest.NewRecorder()
	view.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("checkpoint direct access status = %d", response.Code)
	}
}

func TestFileViewHoldsArchiveLockUntilResponseCompletes(t *testing.T) {
	store, data := testStore(t)
	writeGUIArchive(t, data.Path, "2026/11/07/10/0000.tar", "data")
	archivePath := filepath.Join(data.Path, "2026", "11", "07", "10", "0000.tar")
	request := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/files/2026/11/07/10/0000.tar?download=1", nil), map[string]string{"path": "2026/11/07/10/0000.tar"})
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	writer := &blockingBrowseWriter{ResponseRecorder: httptest.NewRecorder(), started: started, release: release}
	go func() { FileView(store).ServeHTTP(writer, request); close(done) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("archive download did not start")
	}
	if removed, err := archive.Default.TryDelete(t.Context(), archivePath); err != nil || removed {
		t.Fatalf("cleanup deleted an archive being downloaded: removed=%v, error=%v", removed, err)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("archive download did not finish")
	}
	if removed, err := archive.Default.TryDelete(t.Context(), archivePath); err != nil || !removed {
		t.Fatalf("archive lock was not released: removed=%v, error=%v", removed, err)
	}
}

type blockingBrowseWriter struct {
	*httptest.ResponseRecorder
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (w *blockingBrowseWriter) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.started); <-w.release })
	return w.ResponseRecorder.Write(data)
}

func TestRedirectPreservesBucketAndToken(t *testing.T) {
	testStore(t)
	t.Setenv(config.READ_TOKEN, "read-secret")
	config.Settings.Set(config.READ_TOKEN, "", "")
	request := httptest.NewRequest(http.MethodGet, "/redirect?file=20261107-1036-40f1-b34f-02d7517a01d3&bucket=logs&token=read-secret", nil)
	response := httptest.NewRecorder()
	Redirect(response, request)
	want := "/buckets/logs/get/20261107-1036-40f1-b34f-02d7517a01d3?token=read-secret"
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != want {
		t.Fatalf("redirect = %d, %s; want 303, %s", response.Code, response.Header().Get("Location"), want)
	}
}

func testStore(t *testing.T) (*bucket.Store, bucket.Bucket) {
	t.Helper()
	t.Setenv(config.READ_TOKEN, "")
	config.Settings.Set(config.READ_TOKEN, "", "")
	store, err := bucket.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Get(bucket.DefaultName)
	if err != nil {
		t.Fatal(err)
	}
	return store, data
}

func writeGUIArchive(t *testing.T, root, relative, filename string) {
	t.Helper()
	name := filepath.Join(root, filepath.FromSlash(relative))
	payload := []byte("test")
	header := &tar.Header{Name: "20261107-1036-40f1-b34f-02d7517a01d3", Size: int64(len(payload)), Uname: filename, Gname: "text/plain", Format: tar.FormatPAX}
	if _, err := archive.Default.Append(t.Context(), name, header, payload, sha256.Sum256(payload)); err != nil {
		t.Fatal(err)
	}
}
