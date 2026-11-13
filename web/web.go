package web

import "embed"

// TemplateFS embeds all HTML templates (base and child pages)
//
//go:embed templates/*
var TemplateFS embed.FS

// StaticFS embeds all static web assets (css, icons, manifest)
//
//go:embed static/*
var StaticFS embed.FS
