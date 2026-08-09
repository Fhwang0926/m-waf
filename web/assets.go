package web

import (
	"embed"
	"html/template"

	"github.com/Fhwang0926/m-waf/internal/localtime"
)

//go:embed templates/*.html static/*
var Assets embed.FS

func ParseTemplates() (*template.Template, error) {
	return template.New("").Funcs(template.FuncMap{
		"formatKST": localtime.FormatKST,
	}).ParseFS(Assets, "templates/*.html")
}
