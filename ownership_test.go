package main

import "testing"

func TestAcquireDataRoot(t *testing.T) {
	root := t.TempDir()
	first, err := acquireDataRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})
	if second, err := acquireDataRoot(root); err == nil {
		if err := second.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("second server acquired an owned data directory")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireDataRoot(root)
	if err != nil {
		t.Fatalf("released data directory: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
