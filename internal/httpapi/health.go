package httpapi

import (
	"context"
	"net/http"
	"time"
)

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	dbStatus := "up"
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Pool.Ping(ctx); err != nil {
		dbStatus = "down"
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":  "degraded",
			"db":      dbStatus,
			"version": s.Version,
			"error":   err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"db":      dbStatus,
		"version": s.Version,
	})
}
