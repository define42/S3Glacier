package main

import (
	"bytes"
	"embed"
	"glacier/autoclean"
	"glacier/bucket"
	"glacier/config"
	"glacier/gui"
	"glacier/prometheus"
	"glacier/s3"
	"log"
	"net/http"

	"github.com/gabriel-vasile/mimetype"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed static
var assets embed.FS

// InitServer retains the existing entry point for callers that expect a router.
func InitServer() *mux.Router {
	r, err := NewServer()
	if err != nil {
		panic(err)
	}
	return r
}

// NewServer loads immutable bucket definitions before accepting requests.
func NewServer() (*mux.Router, error) {
	config.Settings.Init()
	store, err := bucket.Open(config.Settings.Get(config.DATA_FOLDER))
	if err != nil {
		return nil, err
	}
	s3.ResetS3Users()

	s3WriteToken := config.Settings.Get(config.S3_READ_WRITE_USERS)
	s3.AddS3UserWrite(s3WriteToken)

	s3ReadOnlyUsers := config.Settings.Get(config.S3_READ_ONLY_USERS)
	s3.AddS3UserReadOnly(s3ReadOnlyUsers)

	pcapDetector := func(raw []byte, limit uint32) bool {
		return bytes.HasPrefix(raw, []byte("\xd4\xc3\xb2\xa1"))
	}
	mimetype.Extend(pcapDetector, "application/pcap", ".pcap")
	pcapngDetector := func(raw []byte, limit uint32) bool {
		return bytes.HasPrefix(raw, []byte("\x0a\x0d\x0d\x0a"))
	}
	mimetype.Extend(pcapngDetector, "application/x-pcapng", ".pcapng")

	avroDetector := func(raw []byte, limit uint32) bool {
		return bytes.HasPrefix(raw, []byte("\x4f\x62\x6a\x01"))
	}
	mimetype.Extend(avroDetector, "application/avro", ".avro")

	r := mux.NewRouter()
	r.PathPrefix("/static/").Handler(http.FileServer(http.FS(assets)))
	r.Handle("/", s3.S3Security(s3.ListBuckets(store))).HeadersRegexp("Authorization", "^AWS ").Methods(http.MethodGet)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, assets, "static/index.html")
	}).Methods(http.MethodGet)

	r.HandleFunc("/buckets", manageBuckets(store))
	r.HandleFunc("/buckets/{bucket}", inspectBucket(store))
	r.HandleFunc("/buckets/{bucket}/upload", uploadFile(store)).Methods(http.MethodPost)
	r.HandleFunc("/buckets/{bucket}/rawupload/{id}", rawUpload(store)).Methods(http.MethodPut, http.MethodPost)
	r.HandleFunc("/buckets/{bucket}/get/{id}", downloadFile(store)).Methods(http.MethodGet, http.MethodHead)
	r.Handle("/buckets/{bucket}/files/{path:.*}", gui.FileView(store)).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc("/buckets/{bucket}/files", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"/"+querySuffix(r), http.StatusTemporaryRedirect)
	}).Methods(http.MethodGet)

	r.Handle("/files/{path:.*}", gui.FileView(store)).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc("/uuid", gui.Uuidhello(store)).Methods(http.MethodGet)
	r.HandleFunc("/uuidv1", gui.Uuidv1hello(store)).Methods(http.MethodGet)
	r.HandleFunc("/upload", uploadFile(store)).Methods(http.MethodPost)
	r.HandleFunc("/rawupload/{id}", rawUpload(store)).Methods(http.MethodPut, http.MethodPost)
	r.HandleFunc("/rawupload/{token}/{id}", rawUpload(store)).Methods(http.MethodPut, http.MethodPost)
	r.HandleFunc("/get/{id}", downloadFile(store)).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc("/get/{token}/{id}", downloadFile(store)).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc("/redirect", gui.Redirect).Methods(http.MethodGet)
	r.Handle("/metrics", promhttp.Handler())

	r.Handle("/{bucket}", s3.S3Security(s3.BucketHandler(store)))
	r.Handle("/{bucket}/", s3.S3Security(s3.BucketHandler(store)))
	r.Handle("/{bucket}/{id}", s3.S3Security(s3.ObjectHandler(store)))
	return r, nil
}

func main() {
	r, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}
	go autoclean.AutoClean()
	go prometheus.SystemStat()

	if config.Settings.Has(config.SERVER_DOMAIN) && config.Settings.Has(config.ACME_SERVER) {
		log.Fatal(HTTPSACME([]string{config.Settings.Get(config.SERVER_DOMAIN)}, r, config.Settings.Get(config.ACME_SERVER)))
	} else {
		log.Fatal(http.ListenAndServe(":"+config.Settings.Get(config.SERVER_PORT), r))
	}
}
