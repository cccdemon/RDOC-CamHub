package webui

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
)

// Templates is the parsed template set. Each page template is parsed
// together with layout.html so {{ template "content" . }} resolves
// against the right block. Keeping them in one *template.Template per
// page (rather than a single Lookup map) lets us call ExecuteTemplate
// with the layout name and have the page's "content" block win.
type Templates struct {
	pages map[string]*template.Template
}

// PageData is the common shape every page receives. Pages can wrap this
// in their own struct (embedding PageData) for extra fields.
type PageData struct {
	Title    string
	APIBase  string  // <meta name="api-base">; empty = same origin
	CSRFMeta string  // <meta name="csrf">; empty for unauthenticated pages
	Version  string
	User     *PageUser
	Flash    string  // one-shot status/error chip
}

// PageUser is what the layout's nav uses to render the signed-in chip.
// nil = unauthenticated page (login screen).
type PageUser struct {
	Email string
	Role  string
}

// loadTemplates parses every page template against layout.html. Failure
// here aborts startup, surfacing template syntax errors immediately
// instead of at first render.
func loadTemplates(efs fs.FS) (*Templates, error) {
	layout, err := fs.ReadFile(efs, "templates/layout.html")
	if err != nil {
		return nil, fmt.Errorf("webui: read layout template: %w", err)
	}

	entries, err := fs.ReadDir(efs, "templates")
	if err != nil {
		return nil, fmt.Errorf("webui: read templates dir: %w", err)
	}

	t := &Templates{pages: map[string]*template.Template{}}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == "layout.html" {
			continue
		}
		page, err := fs.ReadFile(efs, "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("webui: read %s: %w", name, err)
		}
		tpl := template.New("layout.html")
		if _, err := tpl.Parse(string(layout)); err != nil {
			return nil, fmt.Errorf("webui: parse layout for %s: %w", name, err)
		}
		if _, err := tpl.Parse(string(page)); err != nil {
			return nil, fmt.Errorf("webui: parse %s: %w", name, err)
		}
		t.pages[name] = tpl
	}
	return t, nil
}

// Render writes a page to w using the layout as the root template. The
// page's `{{define "content"}}…{{end}}` block fills the layout's
// `{{template "content" .}}` slot.
func (t *Templates) Render(w http.ResponseWriter, status int, page string, data any) error {
	tpl, ok := t.pages[page]
	if !ok {
		return fmt.Errorf("webui: unknown page %q", page)
	}

	// Render to a buffer first so a template error never produces a
	// half-streamed response that the browser would treat as a partial
	// success.
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		return fmt.Errorf("webui: execute %s: %w", page, err)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
	return nil
}
