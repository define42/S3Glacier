package main

import (
	"bytes"
	"context"
	"glacier/shared"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestS3(t *testing.T) {
	endpoint := "localhost"
	accessKeyID := "aaaaaaaaaaaaaaaaaaaa"
	secretAccessKey := "sssssssssssssssssssssssssssssssssssssssssss"
	test_uuid := shared.GenerateTimeUUID()
	useSSL := false

	r := InitServer()
	go http.ListenAndServe(":80", r)

	// Initialize minio client object.
	server, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV2(accessKeyID, secretAccessKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		t.Fatalf("Panic:%v", err)
	}
	//server.TraceOn(os.Stderr)

	data := []byte("this is some data stored as a byte slice in Go Lang!")
	reader := bytes.NewReader(data)
	_, err = server.PutObject(context.Background(), "data", test_uuid, reader, (int64)(len(data)), minio.PutObjectOptions{})
	if err != nil {
		t.Fatalf("S3 upload panic: %v", err)
	}

	file2, err := server.GetObject(context.Background(), "data", test_uuid, minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("Unable to GetObject Error:%v", err)
	}
	outputData, err2 := ioutil.ReadAll(file2)
	if err2 != nil {
		t.Fatalf("Unable to read file! Error:%v", err2)
	}
	if bytes.Compare(outputData, data) != 0 {
		t.Fatalf("Upload/download did not pass! Want:\"%v\" Have:\"%v\"", string(data), string(outputData))
	}

}

func TestServer(t *testing.T) {
	test_uuid := shared.GenerateTimeUUID()
	data := []byte("this is some data stored as a byte slice in Go Lang!")
	r := InitServer()
	go http.ListenAndServe(":8000", r)

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("file", test_uuid)
	if err != nil {
		t.Fatalf("Panic error writing to buffer")
	}

	reader := bytes.NewReader(data)
	io.Copy(fileWriter, reader)
	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()
	resp, err := http.Post("http://localhost:8000/upload", contentType, bodyBuf)
	if err != nil {
		t.Fatalf("Panic unable to upload file")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("Wrong response-code! Have:\"%v\"", resp.Status)
	}

	getresp, err := http.Get("http://localhost:8000/get/" + test_uuid)
	if err != nil {
		t.Fatalf("Unable to get file! Error:%v", err)
	}

	getbody, err := ioutil.ReadAll(getresp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	if bytes.Compare(getbody, data) != 0 {
		t.Fatalf("Upload/download did not pass! Want:\"%v\" Have:\"%v\"", string(data), string(getbody))
	}
}
