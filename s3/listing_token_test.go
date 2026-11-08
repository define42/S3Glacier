package s3

import (
	"glacier/bucket"
	"strings"
	"testing"
	"time"
)

func TestListTokenScope(t *testing.T) {
	t.Parallel()
	b := bucket.Bucket{Name: "archive", Path: "/data/buckets/archive", CreatedAt: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)}
	q := listQuery{prefix: "2026", delimiter: "-", maxKeys: 3}
	const after = "20261107-"
	token, err := encodeListToken(after, b, q, "secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*bucket.Bucket, *listQuery, *string)
		valid  bool
	}{
		{name: "same request", valid: true},
		{name: "different page size", change: func(_ *bucket.Bucket, q *listQuery, _ *string) { q.maxKeys = 1000 }, valid: true},
		{name: "different encoding", change: func(_ *bucket.Bucket, q *listQuery, _ *string) { q.encodeURL = true }, valid: true},
		{name: "different owner display", change: func(_ *bucket.Bucket, q *listQuery, _ *string) { q.fetchOwner = true }, valid: true},
		{name: "start-after superseded", change: func(_ *bucket.Bucket, q *listQuery, _ *string) { q.startAfter, q.after = "arbitrary", "arbitrary" }, valid: true},
		{name: "other bucket", change: func(b *bucket.Bucket, _ *listQuery, _ *string) { b.Name = "other" }},
		{name: "recreated bucket", change: func(b *bucket.Bucket, _ *listQuery, _ *string) { b.CreatedAt = b.CreatedAt.Add(time.Second) }},
		{name: "other data root", change: func(b *bucket.Bucket, _ *listQuery, _ *string) { b.Path = "/other/buckets/archive" }},
		{name: "different prefix", change: func(_ *bucket.Bucket, q *listQuery, _ *string) { q.prefix = "202611" }},
		{name: "different delimiter", change: func(_ *bucket.Bucket, q *listQuery, _ *string) { q.delimiter = "/" }},
		{name: "different routing setting", change: func(_ *bucket.Bucket, q *listQuery, _ *string) { q.extended = true }},
		{name: "different secret", change: func(_ *bucket.Bucket, _ *listQuery, secret *string) { *secret = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, q, secret := b, q, "secret"
			if tc.change != nil {
				tc.change(&b, &q, &secret)
			}
			got, err := decodeListToken(token, b, q, secret)
			if tc.valid {
				if err != nil || got != after {
					t.Fatalf("cursor=%q err=%v, want %q", got, err, after)
				}
			} else if err == nil {
				t.Fatalf("token accepted outside its scope: %q", got)
			}
		})
	}
	for _, tc := range []struct{ name, token string }{
		{name: "empty", token: ""},
		{name: "truncated", token: token[:len(token)/2]},
		{name: "changed signature", token: token + "A"},
		{name: "changed payload", token: "A" + token[1:]},
		{name: "extra component", token: token + ".extra"},
		{name: "oversized", token: strings.Repeat("a", 4097)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeListToken(tc.token, b, q, "secret"); err == nil {
				t.Fatal("malformed or tampered token accepted")
			}
		})
	}
}
