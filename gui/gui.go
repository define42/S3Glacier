package gui

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"glacier/shared"
	"io"
	"net/http"
	"os"
	"path"

	"github.com/google/uuid"
)

type MyUUID struct {
	Uuid          string
	ContainerFile string
}

func Uuidhello(w http.ResponseWriter, req *http.Request) {
	idString := shared.GenerateTimeUUID()
	containerFile, idString, _ := shared.GetContainerFile(idString)
	myuuid := &MyUUID{Uuid: idString, ContainerFile: containerFile}
	jData, err := json.Marshal(myuuid)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jData)
	}
}
func Uuidv1hello(w http.ResponseWriter, req *http.Request) {
	uuidv1, _ := uuid.NewUUID()
	idString := uuidv1.String()
	containerFile, idString, _ := shared.GetContainerFile(idString)
	myuuid := &MyUUID{Uuid: idString, ContainerFile: containerFile}
	jData, err := json.Marshal(myuuid)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jData)
	}
}

func Redirect(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("file")
	if id != "" {
		http.Redirect(w, r, "get/"+id, http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintln(w, "Error Retrieving the File")
}

func FileView(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := 0
		fileExt := path.Ext(r.URL.String())
		if fileExt != ".tar" {
			next.ServeHTTP(w, r)
			return
		}
		tarFile, err := os.Open("." + r.URL.String())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "open tar file failed", err)
			return
		}
		defer tarFile.Close()

		tr := tar.NewReader(tarFile)
		fmt.Fprintf(w, "<html><head><link href=../../../../../static/bootstrap.css rel=stylesheet></head>")
		fmt.Fprintf(w, "<table class=\"table table-hover\">")
		fmt.Fprintf(w, "<tr><th>ID</th><th>Name</th>")
		fmt.Fprintf(w, "<th>GzipSize</th>")
		fmt.Fprintf(w, "<th>RealSize</th>")
		fmt.Fprintf(w, "<th>GzipRatio</th>")
		fmt.Fprintf(w, "<th>Filename</th>")
		fmt.Fprintf(w, "<th>MimeType</th>")
		fmt.Fprintf(w, "<th>Compressed</th>")
		fmt.Fprintf(w, "<th>Metadata</th><tr>")
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, "open tar file failed", err)
				break
			}
			metadata, _ := json.Marshal(hdr.PAXRecords)
			fmt.Fprintf(w, "<tr><td>%d</td>", count)
			fmt.Fprintf(w, "<td><a href=..\\..\\..\\..\\..\\get\\%v>%v</a>", hdr.Name, hdr.Name)
			if hdr.Gname == "application/avro" {
				fmt.Fprintf(w, "<a href=..\\..\\..\\..\\..\\get\\%v?parse=avro> <img src=/static/avro.svg></a>", hdr.Name)
			}
			fmt.Fprintf(w, "</td>")
			fmt.Fprintf(w, "<td>%d</td>", hdr.Size)
			fmt.Fprintf(w, "<td>%d</td>", hdr.Uid)
			fmt.Fprintf(w, "<td>%.2f</td>", (float64)((float64)(hdr.Size)/(float64)(hdr.Uid)))
			fmt.Fprintf(w, "<td>%v</td>", hdr.Uname)
			fmt.Fprintf(w, "<td>%v</td>", hdr.Gname)
			fmt.Fprintf(w, "<td>%v</td>", hdr.Mode)
			fmt.Fprintf(w, "<td>%v</td><tr>", string(metadata))
			count = count + 1
		}
		fmt.Fprintf(w, "</table>")
	})
}
