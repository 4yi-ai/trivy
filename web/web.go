// Package web embeds the server-rendered UI (HTML templates + static assets).
// The embed lives here, next to the files, because //go:embed paths are
// relative to the source file's directory — putting it in cmd/codescan would
// make it look for cmd/codescan/web, which does not exist.
package web

import "embed"

// FS holds templates/* and static/* at its root.
//
//go:embed all:static templates
var FS embed.FS
