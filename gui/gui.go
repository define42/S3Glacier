package gui

import (
	"archive/tar"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"glacier/archive"
	"glacier/bucket"
	"glacier/shared"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// MyUUID is the UUID handlers' JSON response, including the selected bucket's
// fixed archive count and the resolved filesystem path in ContainerFile.
type MyUUID struct {
	Uuid            string
	ContainerFile   string
	Bucket          string
	TarFilesPerHour int
}

// Uuidhello returns a read-authorized handler that generates a timestamped
// UUIDv4 and its predicted archive path in the requested bucket.
func Uuidhello(store *bucket.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeUUID(store, w, r, shared.GenerateTimeUUID())
	}
}

// Uuidv1hello returns a read-authorized handler that generates a UUIDv1 and its
// predicted archive path in the requested bucket. Generation failures return 500.
func Uuidv1hello(store *bucket.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.NewUUID()
		if err != nil {
			http.Error(w, "Unable to generate UUID", http.StatusInternalServerError)
			return
		}
		writeUUID(store, w, r, id.String())
	}
}

func writeUUID(store *bucket.Store, w http.ResponseWriter, r *http.Request, id string) {
	if !shared.AuthorizeRead(w, r) {
		return
	}
	b, err := store.Get(shared.RequestBucket(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	container, id, err := shared.GetBucketContainerFile(b, id)
	if err != nil {
		http.Error(w, "Unable to resolve UUID", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(MyUUID{Uuid: id, ContainerFile: container, Bucket: b.Name, TarFilesPerHour: b.TarFilesPerHour})
}

// Redirect authorizes reading and redirects the file query parameter to the
// selected bucket's download URL, preserving the read token. A missing file
// parameter returns 400; bucket and object existence are checked by the target.
func Redirect(w http.ResponseWriter, r *http.Request) {
	if !shared.AuthorizeRead(w, r) {
		return
	}
	id := r.URL.Query().Get("file")
	if id == "" {
		http.Error(w, "Enter a file UUID", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, shared.ObjectURL(shared.RequestBucket(r), id, shared.RequestToken(r)), http.StatusSeeOther)
}

type browseEntry struct {
	Name string
	URL  string
	Kind string
}

type archiveRow struct {
	ID           string
	URL          string
	AvroURL      string
	StoredSize   int64
	OriginalSize int64
	Filename     string
	MimeType     string
	Compressed   bool
	Metadata     string
}

type browsePage struct {
	Bucket      bucket.Bucket
	Path        string
	ParentURL   string
	DownloadURL string
	IsArchive   bool
	Entries     []browseEntry
	Rows        []archiveRow
}

var browseTemplate = template.Must(template.New("browse").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Bucket.Name}} archive files</title><link href="/static/bootstrap.css" rel="stylesheet"></head>
<body><main class="container-fluid py-4"><nav class="mb-3"><a href="/">Home</a>{{if .ParentURL}} · <a href="{{.ParentURL}}">Parent folder</a>{{end}}</nav>
<h1>{{.Bucket.Name}} archive files</h1><p>{{.Bucket.TarFilesPerHour}} TAR files per hour, fixed when the bucket is created.</p>
<p>Path: <code>{{if .Path}}{{.Path}}{{else}}/{{end}}</code></p>
{{if .IsArchive}}<p><a href="{{.DownloadURL}}">Download TAR archive</a></p><div class="table-responsive"><table class="table table-hover">
<thead><tr><th scope="col">UUID</th><th scope="col">Stored bytes</th><th scope="col">Original bytes</th><th scope="col">Filename</th><th scope="col">Type</th><th scope="col">Compressed</th><th scope="col">Metadata</th></tr></thead><tbody>
{{range .Rows}}<tr><td><a href="{{.URL}}">{{.ID}}</a>{{if .AvroURL}} · <a href="{{.AvroURL}}">View JSON</a>{{end}}</td><td>{{.StoredSize}}</td><td>{{.OriginalSize}}</td><td>{{.Filename}}</td><td>{{.MimeType}}</td><td>{{.Compressed}}</td><td><code>{{.Metadata}}</code></td></tr>
{{else}}<tr><td colspan="7">This archive has no objects.</td></tr>{{end}}</tbody></table></div>
{{else}}<table class="table table-hover"><thead><tr><th scope="col">Name</th><th scope="col">Type</th></tr></thead><tbody>
{{range .Entries}}<tr><td><a href="{{.URL}}">{{.Name}}</a></td><td>{{.Kind}}</td></tr>{{else}}<tr><td colspan="2">No archive files in this folder yet.</td></tr>{{end}}</tbody></table>{{end}}
</main></body></html>`))

// FileView exposes only a bucket's dated archive tree, never its configuration
// files or another bucket's storage directory. TAR reads use the shared archive
// coordinator before opening or stating their data and hold the read lock until
// the response finishes. Checkpoints and the internal manifest are not listed.
func FileView(store *bucket.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !shared.AuthorizeRead(w, r) {
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		b, err := store.Get(shared.RequestBucket(r))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		relative := strings.TrimSuffix(mux.Vars(r)["path"], "/")
		if !validBrowsePath(relative) {
			http.NotFound(w, r)
			return
		}
		root, err := os.OpenRoot(b.Path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer root.Close()
		// These security checks do not open archive data. The archive coordinator
		// also rejects symlinks under its key lock before opening or recovering.
		if !regularBrowsePath(root, relative) {
			http.NotFound(w, r)
			return
		}
		token := shared.RequestToken(r)
		if path.Ext(relative) == ".tar" {
			serveArchiveView(w, r, b, relative, token)
			return
		}
		name := relative
		if name == "" {
			name = "."
		}
		file, err := root.Open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			http.Error(w, "Unable to read archive path", http.StatusInternalServerError)
			return
		}
		if !info.IsDir() {
			http.NotFound(w, r)
			return
		}
		entries, err := file.ReadDir(-1)
		if err != nil {
			http.Error(w, "Unable to list archive folder", http.StatusInternalServerError)
			return
		}
		page := newBrowsePage(b, relative, token)
		slices.SortFunc(entries, func(a, b os.DirEntry) int { return cmp.Compare(a.Name(), b.Name()) })
		for _, entry := range entries {
			child := path.Join(relative, entry.Name())
			if !validBrowsePath(child) || entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			kind := "Folder"
			if strings.HasSuffix(child, ".tar") {
				if !entry.Type().IsRegular() {
					continue
				}
				kind = "TAR archive"
			} else if !entry.IsDir() {
				continue
			}
			page.Entries = append(page.Entries, browseEntry{Name: entry.Name(), URL: browseURL(b.Name, child, token), Kind: kind})
		}
		writeBrowsePage(w, page)
	})
}

func newBrowsePage(b bucket.Bucket, relative, token string) browsePage {
	page := browsePage{Bucket: b, Path: relative}
	if relative != "" {
		parent := path.Dir(relative)
		if parent == "." {
			parent = ""
		}
		page.ParentURL = browseURL(b.Name, parent, token)
	}
	return page
}

func serveArchiveView(w http.ResponseWriter, r *http.Request, b bucket.Bucket, relative, token string) {
	file, err := archive.Default.TryOpen(r.Context(), filepath.Join(b.Path, filepath.FromSlash(relative)))
	if errors.Is(err, archive.ErrBusy) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Archive is busy; try again", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
		} else if errors.Is(err, archive.ErrUnavailable) {
			http.Error(w, "Archive is unavailable after a storage failure", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "Unable to open committed archive", http.StatusInternalServerError)
		}
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		http.Error(w, "Unable to read archive path", http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(relative)))
		http.ServeContent(w, r, info.Name(), info.ModTime(), file)
		return
	}
	page := newBrowsePage(b, relative, token)
	page.IsArchive = true
	page.DownloadURL = addQuery(browseURL(b.Name, relative, token), "download", "1")
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Unable to read TAR archive", http.StatusInternalServerError)
			return
		}
		if archive.IsInternalEntry(header) {
			continue
		}
		metadata, _ := json.Marshal(header.PAXRecords)
		row := archiveRow{ID: header.Name, URL: shared.ObjectURL(b.Name, header.Name, token),
			StoredSize: header.Size, OriginalSize: header.Size, Filename: header.Uname,
			MimeType: header.Gname, Compressed: header.Mode == 1, Metadata: string(metadata)}
		if row.Compressed {
			row.OriginalSize = int64(header.Uid)
		}
		if row.MimeType == "application/avro" {
			row.AvroURL = addQuery(row.URL, "parse", "avro")
		}
		page.Rows = append(page.Rows, row)
	}
	writeBrowsePage(w, page)
}

func writeBrowsePage(w http.ResponseWriter, page browsePage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	browseTemplate.Execute(w, page)
}

func validBrowsePath(relative string) bool {
	if relative == "" {
		return true
	}
	if strings.Contains(relative, "\\") {
		return false
	}
	parts := strings.Split(relative, "/")
	if len(parts) > 5 {
		return false
	}
	date := []string{"0000", "01", "01", "00"}
	for i, part := range parts {
		if i == 4 {
			if len(part) <= 4 || path.Ext(part) != ".tar" {
				return false
			}
			break
		}
		width := 2
		if i == 0 {
			width = 4
		}
		if len(part) != width || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) != -1 {
			return false
		}
		date[i] = part
	}
	_, err := time.Parse("2006/01/02/15", strings.Join(date, "/"))
	return err == nil
}

func regularBrowsePath(root *os.Root, relative string) bool {
	if relative == "" {
		return true
	}
	parts := strings.Split(relative, "/")
	for i := range parts {
		info, err := root.Lstat(path.Join(parts[:i+1]...))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

func browseURL(name, relative, token string) string {
	value := "/buckets/" + url.PathEscape(name) + "/files/"
	if relative != "" {
		parts := strings.Split(relative, "/")
		for i := range parts {
			parts[i] = url.PathEscape(parts[i])
		}
		value += strings.Join(parts, "/")
		if path.Ext(relative) != ".tar" {
			value += "/"
		}
	}
	if token != "" {
		value += "?" + url.Values{"token": {token}}.Encode()
	}
	return value
}

func addQuery(value, key, item string) string {
	parsed, _ := url.Parse(value)
	query := parsed.Query()
	query.Set(key, item)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
