// Package gui implements the browser's UUID, download redirect, and archive
// browsing handlers. Requests use the selected bucket and the HTTP read token;
// archive browsing hides bucket definitions, checkpoints, and internal manifests
// and rejects symbolic links. TAR reads retain the archive coordinator's shared
// lock through the response, including raw TAR downloads.
package gui
