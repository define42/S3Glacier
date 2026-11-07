package s3

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestS3SecurityResetUsers(t *testing.T) {
	ResetS3Users()
	t.Cleanup(ResetS3Users)
	AddS3UserWrite("writer=base64=secret;")
	request := httptest.NewRequest("GET", "/", nil)
	request = SignV2(*request, "writer", "base64=secret", false)
	handler := S3Security(func(w http.ResponseWriter, r *http.Request, user S3User) {
		if !user.Write || !user.Read {
			t.Error("write user lost permissions")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("valid credentials returned %d: %s", response.Code, response.Body.String())
	}
	ResetS3Users()
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("reset credentials still authenticated: %d", response.Code)
	}
}
