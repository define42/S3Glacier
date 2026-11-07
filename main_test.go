package main

import (
	"bytes"
	"glacier/shared"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestS3(t *testing.T) {
	accessKeyID := "s3usernameABC"
	secretAccessKey := "s3passwordABC"
	t.Setenv("S3_READ_WRITE_USERS", accessKeyID+"="+secretAccessKey)
	testServer := newTestServer(t)
	endpoint := strings.TrimPrefix(testServer.URL, "http://")
	test_uuid := shared.GenerateTimeUUID()
	useSSL := false

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
	_, err = server.PutObject(t.Context(), "data", test_uuid, reader, (int64)(len(data)), minio.PutObjectOptions{})
	if err != nil {
		t.Fatalf("S3 upload panic: %v", err)
	}

	file2, err := server.GetObject(t.Context(), "data", test_uuid, minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("Unable to GetObject Error:%v", err)
	}
	defer file2.Close()
	outputData, err2 := io.ReadAll(file2)
	if err2 != nil {
		t.Fatalf("Unable to read file! Error:%v", err2)
	}
	if bytes.Compare(outputData, data) != 0 {
		t.Fatalf("Upload/download did not pass! Want:\"%v\" Have:\"%v\"", string(data), string(outputData))
	}

}

func TestServer(t *testing.T) {
	t.Setenv("S3_READ_WRITE_USERS", "")
	testServer := newTestServer(t)
	test_uuid := shared.GenerateTimeUUID()
	data := []byte("this is some data stored as a byte slice in Go Lang!")

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("file", test_uuid)
	if err != nil {
		t.Fatalf("Error creating upload form: %v", err)
	}

	reader := bytes.NewReader(data)
	if _, err := io.Copy(fileWriter, reader); err != nil {
		t.Fatalf("Error writing upload data: %v", err)
	}
	contentType := bodyWriter.FormDataContentType()
	if err := bodyWriter.Close(); err != nil {
		t.Fatalf("Error closing upload form: %v", err)
	}
	resp, err := testServer.Client().Post(testServer.URL+"/upload", contentType, bodyBuf)
	if err != nil {
		t.Fatalf("Unable to upload file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Wrong response-code! Have:\"%v\"", resp.Status)
	}

	getresp, err := testServer.Client().Get(testServer.URL + "/get/" + test_uuid)
	if err != nil {
		t.Fatalf("Unable to get file! Error:%v", err)
	}
	defer getresp.Body.Close()
	if getresp.StatusCode != http.StatusOK {
		t.Fatalf("Wrong download response-code! Have:%q", getresp.Status)
	}

	getbody, err := io.ReadAll(getresp.Body)
	if err != nil {
		t.Fatalf("Unable to read file: %v", err)
	}

	if bytes.Compare(getbody, data) != 0 {
		t.Fatalf("Upload/download did not pass! Want:\"%v\" Have:\"%v\"", string(data), string(getbody))
	}
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("DATA_FOLDER", "files")
	t.Setenv("READ_TOKEN", "")
	t.Setenv("WRITE_TOKEN", "")
	t.Setenv("S3_READ_ONLY_USERS", "")
	t.Setenv("EXTEND_LIFE_SUPPORT", "false")
	server := httptest.NewServer(InitServer())
	t.Cleanup(server.Close)
	return server
}
