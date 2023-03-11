package main

import (
	"bytes"
	"context"
	"fmt"
	"glacier/autoclean"
	"glacier/config"
	"glacier/gui"
	"glacier/prometheus"
	"glacier/s3"
	"glacier/shared"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gabriel-vasile/mimetype"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var ctx = context.Background()

func rawUpload(w http.ResponseWriter, r *http.Request) {
	prometheus.RawUploadProcessed.Inc()
	vars := mux.Vars(r)
	id, ok := vars["id"]
	if !ok {
		fmt.Println("id is missing in parameters")
	}
	token, ok := vars["token"]
	if !ok {
		fmt.Println("token is missing in parameters")
	}
	fmt.Println(token)
	if config.Settings.Has(config.WRITE_TOKEN) && token != config.Settings.Get(config.WRITE_TOKEN) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Access forbidden")
		return
	}
	fileBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, err)
		return
	}
	defer r.Body.Close()
	id, containerFile, err := shared.SharedUpload(r, token, id, fileBytes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, err)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<html><a href=get/%v>%v</a> <br><a href=%v>%v</a>", id, id, containerFile, containerFile)
}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.ParseMultipartForm(10 << 30)
	tokenList := r.MultipartForm.Value["token"]
	token := ""
	if len(tokenList) > 0 {
		token = tokenList[0]
	}
	fmt.Println(token)

	files := r.MultipartForm.File["file"]
	savedList := make(map[string]string)
	for _, fileHeader := range files {

		//file, handler, err := r.FormFile("file")
		file, err := fileHeader.Open()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Error Retrieving the File")
			fmt.Fprintln(w, err)
			fmt.Println("Error Retrieving the File", err)
			return
		}
		defer file.Close()

		fileUUID := fileHeader.Filename
		generateNewUUID := r.URL.Query().Get("newuuid")
		if generateNewUUID != "" {
			fileUUID = shared.GenerateTimeUUID()
		}
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, err)
			return
		}
		id, containerFile, err := shared.SharedUpload(r, token, fileUUID, fileBytes)
		savedList[id] = containerFile
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, err)
			return
		}
	}
	if len(savedList) > 0 {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><table border=1><tr><th>UUID</th><th>TAR File</th></tr>")
		for key, value := range savedList {
			fmt.Fprintf(w, "<tr><td><a href=get/%v>%v</a></td><td><a href=%v>%v</a></td></tr>", key, key, value, value)
		}
		fmt.Fprintf(w, "</table>")
	}
}

func InitServer() *mux.Router {
	config.Settings.Init()

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

	err := os.MkdirAll(config.Settings.Get(config.DATA_FOLDER), 0700)
	if err != nil {
		fmt.Println(err)
		log.Fatal("Panic unable to create folder:", config.Settings.Get(config.DATA_FOLDER))
	}
	r := mux.NewRouter()
	filesfs := http.StripPrefix("/files/", http.FileServer(http.Dir(config.Settings.Get(config.DATA_FOLDER))))
	r.PathPrefix("/files/").Handler(gui.FileView(filesfs))
	staticfs := http.StripPrefix("/static/", http.FileServer(http.Dir("/static")))
	r.PathPrefix("/static/").Handler(staticfs)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		http.ServeFile(w, r, "/static/index.html")
	})

	r.HandleFunc("/uuid", gui.Uuidhello)
	r.HandleFunc("/uuidv1", gui.Uuidv1hello)
	r.Handle("/data/", s3.S3Security(s3.S3Bucket))
	r.HandleFunc("/upload", uploadFile)
	r.HandleFunc("/rawupload/{id}", rawUpload)
	r.HandleFunc("/rawupload/{token}/{id}", rawUpload)
	r.HandleFunc("/get/{id}", shared.GetFile)
	r.HandleFunc("/get/{token}/{id}", shared.GetFile)
	r.HandleFunc("/redirect", gui.Redirect)
	r.Handle("/data/{id}", s3.S3Security(s3.S3Handler))
	r.Handle("/{token}/{id}", s3.S3Security(s3.S3Handler))
	r.Handle("/metrics", promhttp.Handler())
	return r
}

func main() {
	r := InitServer()
	go autoclean.AutoClean()
	go prometheus.SystemStat()

	if config.Settings.Has(config.SERVER_DOMAIN) && config.Settings.Has(config.ACME_SERVER) {
		log.Fatal(HTTPSACME([]string{config.Settings.Get(config.SERVER_DOMAIN)}, r, config.Settings.Get(config.ACME_SERVER)))
	} else {
		http.ListenAndServe(":"+config.Settings.Get(config.SERVER_PORT), r)
	}
}
