package web

import "embed"

// Assets embeds the compiled static frontend files.
//go:embed all:dist
var Assets embed.FS
