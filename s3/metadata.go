package s3

import (
	"errors"
	"fmt"
	"glacier/archive"
	"glacier/shared"
	"net/http"
	"slices"
	"strings"
)

// objectMetadata runs after S3Security has verified and removed wire framing.
// Only V4 authenticates ordinary query parameters, so V2 query metadata remains
// an unsupported operation parameter and cannot become stored object metadata.
func objectMetadata(r *http.Request) (shared.ObjectMetadata, error) {
	metadata, err := shared.ParseObjectMetadata(r.Header)
	if err != nil {
		return metadata, err
	}
	if _, verified := V4Info(r); !verified {
		return metadata, nil
	}
	queryHeaders := make(http.Header)
	for name, values := range r.URL.Query() {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") {
			queryHeaders[name] = values
		}
	}
	if len(queryHeaders) == 0 {
		return metadata, nil
	}
	queryMetadata, err := shared.ParseObjectMetadata(queryHeaders)
	if err != nil {
		return metadata, err
	}
	combined := r.Header.Clone()
	for key, value := range queryMetadata.User {
		if headerValue, exists := metadata.User[key]; exists {
			if headerValue != value {
				return metadata, fmt.Errorf("%w: header and query metadata conflict", archive.ErrInvalidEntry)
			}
		}
	}
	for name, values := range queryHeaders {
		key := strings.TrimPrefix(strings.ToLower(name), "x-amz-meta-")
		if _, exists := metadata.User[key]; !exists {
			// Keep the wire values: parsing an already MIME-decoded value again
			// could accidentally decode a nested RFC 2047 word twice.
			combined[name] = slices.Clone(values)
		}
	}
	// Validate the combined budget, rather than accepting two separate limits.
	return shared.ParseObjectMetadata(combined)
}

func writeMetadataError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, shared.ErrMetadataTooLarge) {
		writeS3Error(w, r, http.StatusBadRequest, "MetadataTooLarge", "The object metadata exceeds the supported size limit.")
		return
	}
	writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "The object metadata is invalid or contains conflicting values.")
}
