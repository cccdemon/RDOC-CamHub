package webui

import (
	"net/http"
)

// LoginPage renders the login form. UI-M0: the form submits via JS in
// camhub.js (fetch → APIBase + /v1/auth/login), so this handler is a
// pure GET — there is no POST counterpart here. POST handling lives in
// the JSON API at /v1/auth/login.
func (s *Server) LoginPage(w http.ResponseWriter, r *http.Request) {
	if err := s.Templates.Render(w, http.StatusOK, "login.html", PageData{
		Title:   "Sign in · CamHub",
		APIBase: s.APIBase,
		Version: s.AppVersion,
	}); err != nil {
		s.Logger.Error("webui: render login", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// Dashboard is the post-login landing. UI-M0 renders a placeholder; the
// real fleet grid arrives in UI-M1 gated on backend Milestone 1. The
// user email/role chip and live data are fetched client-side from
// /v1/auth/me + the device endpoints, so this handler stays
// dependency-free of the auth package.
//
// Mount behind a redirect-to-/login wrapper, not the JSON RequireSession
// (which writes 401 JSON instead of redirecting).
func (s *Server) Dashboard(w http.ResponseWriter, r *http.Request) {
	if err := s.Templates.Render(w, http.StatusOK, "dashboard.html", PageData{
		Title:   "Fleet · CamHub",
		APIBase: s.APIBase,
		Version: s.AppVersion,
	}); err != nil {
		s.Logger.Error("webui: render dashboard", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
