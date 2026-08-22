package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GeneJie199/infrastructure-discovery/internal/dbmeta"
	"github.com/GeneJie199/infrastructure-discovery/pkg/infrascout"
)

type reviewRequest struct {
	Classification infrascout.DriftClassification `json:"classification"`
	Actor          string                         `json:"actor"`
	Note           string                         `json:"note"`
	ExpiresAt      string                         `json:"expires_at,omitempty"`
}

const mutationHeader = "X-InfraScout-Action"

func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	if !s.reviewsAllowed(w, r) {
		return
	}
	var input reviewRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid review: "+err.Error())
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeAPIError(w, http.StatusBadRequest, "review request must contain one JSON object")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	report, decisions, err := s.loadReviewState(now)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	fingerprint, resourceID, kind, err := infrascout.FindDriftItem(report, r.PathValue("fingerprint"), "")
	if err != nil {
		writeAPIError(w, http.StatusNotFound, err.Error())
		return
	}
	decision := infrascout.DriftDecision{Fingerprint: fingerprint, ResourceID: resourceID, ChangeKind: kind, Classification: input.Classification, Actor: strings.TrimSpace(input.Actor), Note: strings.TrimSpace(input.Note), DecidedAt: infrascout.FormatTime(now), ExpiresAt: strings.TrimSpace(input.ExpiresAt)}
	if err := decisions.Upsert(decision, now); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := writeJSONAtomic(filepath.Join(s.cfg.StateDir, "decisions.json"), decisions); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	infrascout.ApplyDecisions(&report, decisions, now)
	if err := writeJSONAtomic(filepath.Join(s.cfg.StateDir, "drift.json"), report); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeAPIJSON(w, report)
}

func (s *Server) handlePromote(w http.ResponseWriter, r *http.Request) {
	if !s.reviewsAllowed(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	report, decisions, err := s.loadReviewState(now)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	fingerprint, resourceID, kind, err := infrascout.FindDriftItem(report, r.PathValue("fingerprint"), "")
	if err != nil {
		writeAPIError(w, http.StatusNotFound, err.Error())
		return
	}
	classification := reportClassification(report, fingerprint)
	if classification != infrascout.ClassificationApproved && classification != infrascout.ClassificationExpected {
		writeAPIError(w, http.StatusConflict, "only approved or expected changes can be promoted")
		return
	}
	var baseline, current infrascout.Snapshot
	if err := readJSON(filepath.Join(s.cfg.StateDir, "baseline.json"), &baseline); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := readJSON(filepath.Join(s.cfg.StateDir, "current.json"), &current); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if strings.HasPrefix(resourceID, "dbmeta:") {
		var databaseBaseline, databaseCurrent dbmeta.Metadata
		if err := readJSON(filepath.Join(s.cfg.StateDir, "database-baseline.json"), &databaseBaseline); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := readJSON(filepath.Join(s.cfg.StateDir, "database-current.json"), &databaseCurrent); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := dbmeta.PromoteChange(&databaseBaseline, databaseCurrent, resourceID, kind); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := writeJSONAtomic(filepath.Join(s.cfg.StateDir, "database-baseline.json"), databaseBaseline); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := writeJSONAtomic(filepath.Join(s.cfg.StateDir, "database-diff.json"), dbmeta.Compare(databaseBaseline, databaseCurrent)); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		infrascout.PromoteResource(&baseline, current, resourceID, kind)
		baseline.Timestamp = infrascout.FormatTime(now)
		if err := writeJSONAtomic(filepath.Join(s.cfg.StateDir, "baseline.json"), baseline); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	report = infrascout.Compare(baseline, current)
	s.mergeDatabaseDrift(&report)
	infrascout.ApplyDecisions(&report, decisions, now)
	if err := writeJSONAtomic(filepath.Join(s.cfg.StateDir, "drift.json"), report); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeAPIJSON(w, report)
}

func (s *Server) mergeDatabaseDrift(report *infrascout.DiffReport) {
	var databaseDiff dbmeta.Diff
	if err := readJSON(filepath.Join(s.cfg.StateDir, "database-diff.json"), &databaseDiff); err == nil {
		dbmeta.MergeIntoInfraReport(report, databaseDiff)
	}
}

func (s *Server) reviewsAllowed(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get(mutationHeader) != "1" {
		writeAPIError(w, http.StatusForbidden, "mutation request header is required")
		return false
	}
	if s.cfg.StateDir == "" || s.cfg.Demo {
		writeAPIError(w, http.StatusConflict, "start with --state-dir to enable reviews")
		return false
	}
	if s.cfg.AllowRemote {
		writeAPIError(w, http.StatusForbidden, "review mutations are disabled for remote listeners")
		return false
	}
	return true
}

func (s *Server) loadReviewState(now time.Time) (infrascout.DiffReport, infrascout.DecisionSet, error) {
	var report infrascout.DiffReport
	if err := readJSON(filepath.Join(s.cfg.StateDir, "drift.json"), &report); err != nil {
		return report, infrascout.DecisionSet{}, err
	}
	var decisions infrascout.DecisionSet
	err := readJSON(filepath.Join(s.cfg.StateDir, "decisions.json"), &decisions)
	if errors.Is(err, os.ErrNotExist) {
		decisions = infrascout.DecisionSet{Version: infrascout.DecisionSetVersion, Decisions: []infrascout.DriftDecision{}}
	} else if err != nil {
		return report, decisions, err
	}
	if err := decisions.Normalize(now); err != nil {
		return report, decisions, err
	}
	infrascout.ApplyDecisions(&report, decisions, now)
	return report, decisions, nil
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func writeJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".infrascout-web-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(append(data, '\n'))
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("replace %s: %w", path, err)
		}
		return os.Rename(name, path)
	}
	return nil
}

func reportClassification(report infrascout.DiffReport, fingerprint string) infrascout.DriftClassification {
	for _, item := range report.Added {
		if item.Fingerprint == fingerprint {
			return item.Classification
		}
	}
	for _, item := range report.Removed {
		if item.Fingerprint == fingerprint {
			return item.Classification
		}
	}
	for _, item := range report.Changed {
		if item.Fingerprint == fingerprint {
			return item.Classification
		}
	}
	return infrascout.ClassificationUnexpected
}

func writeAPIJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
