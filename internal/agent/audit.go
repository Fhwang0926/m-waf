package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
)

type AuditReader struct {
	path           string
	checkpointPath string
}

func NewAuditReader(path, stateDirectory string) *AuditReader {
	return &AuditReader{path: path, checkpointPath: stateDirectory + "/audit.offset"}
}

func (a *AuditReader) ReadBatch(limit int) ([]model.SecurityEvent, int64, error) {
	if a.path == "" {
		return nil, 0, nil
	}
	f, err := os.Open(a.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	offset := a.checkpoint()
	if info.Size() < offset {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, err
	}
	reader := bufio.NewReaderSize(f, 64<<10)
	events := make([]model.SecurityEvent, 0, limit)
	next := offset
	for {
		line, readErr := reader.ReadBytes('\n')
		if errors.Is(readErr, io.EOF) {
			// ModSecurity may still be writing the final JSON record. Leave an
			// incomplete line uncommitted so the next cycle can retry it.
			break
		}
		if readErr != nil {
			return nil, offset, readErr
		}
		next += int64(len(line))
		line = line[:len(line)-1]
		parsed := parseAuditLine(line)
		remaining := limit - len(events)
		if len(parsed) > remaining {
			parsed = parsed[:remaining]
		}
		events = append(events, parsed...)
		if len(events) >= limit {
			break
		}
	}
	return events, next, nil
}

func (a *AuditReader) Commit(offset int64) error {
	return atomicWrite(a.checkpointPath, []byte(strconv.FormatInt(offset, 10)+"\n"), 0o640)
}

func (a *AuditReader) checkpoint() int64 {
	raw, err := os.ReadFile(a.checkpointPath)
	if err != nil {
		return 0
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || offset < 0 {
		return 0
	}
	return offset
}

func parseAuditLine(line []byte) []model.SecurityEvent {
	var entry struct {
		Transaction struct {
			UniqueID string `json:"unique_id"`
			Time     string `json:"time_stamp"`
			Request  struct {
				Method string `json:"method"`
				URI    string `json:"uri"`
			} `json:"request"`
			Response struct {
				HTTPCode int `json:"http_code"`
			} `json:"response"`
			Messages []struct {
				Message string `json:"message"`
				Details struct {
					RuleID   json.RawMessage `json:"ruleId"`
					Severity string          `json:"severity"`
				} `json:"details"`
			} `json:"messages"`
		} `json:"transaction"`
	}
	if err := json.Unmarshal(line, &entry); err != nil {
		return nil
	}
	when := time.Now().UTC()
	if parsed, err := time.Parse(time.RFC3339Nano, entry.Transaction.Time); err == nil {
		when = parsed.UTC()
	}
	base := sha256.Sum256(line)
	result := make([]model.SecurityEvent, 0, len(entry.Transaction.Messages))
	for i, message := range entry.Transaction.Messages {
		ruleID := strings.Trim(string(message.Details.RuleID), `"`)
		result = append(result, model.SecurityEvent{
			EventID: fmt.Sprintf("%s-%d", hex.EncodeToString(base[:]), i), OccurredAt: when,
			TransactionID: entry.Transaction.UniqueID, Method: entry.Transaction.Request.Method, URI: entry.Transaction.Request.URI,
			StatusCode: entry.Transaction.Response.HTTPCode, RuleID: ruleID, Message: message.Message,
			Severity: message.Details.Severity, Blocked: entry.Transaction.Response.HTTPCode == httpForbidden,
		})
	}
	return result
}

const httpForbidden = 403
