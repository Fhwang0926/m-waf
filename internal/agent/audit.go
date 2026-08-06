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
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
)

type AuditReader struct {
	path           string
	checkpointPath string
}

type AuditPosition struct {
	Device uint64 `json:"device,omitempty"`
	Inode  uint64 `json:"inode,omitempty"`
	Offset int64  `json:"offset"`
}

func (p AuditPosition) Empty() bool { return p.Device == 0 && p.Inode == 0 && p.Offset == 0 }

func NewAuditReader(path, stateDirectory string) *AuditReader {
	return &AuditReader{path: path, checkpointPath: stateDirectory + "/audit.offset"}
}

func (a *AuditReader) ReadBatch(limit int) ([]model.SecurityEvent, AuditPosition, error) {
	if a.path == "" {
		return nil, AuditPosition{}, nil
	}
	f, err := os.Open(a.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, AuditPosition{}, nil
		}
		return nil, AuditPosition{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, AuditPosition{}, err
	}
	device, inode := auditFileIdentity(info)
	position := a.checkpoint()
	if (position.Device != 0 || position.Inode != 0) && (position.Device != device || position.Inode != inode) {
		position.Offset = 0
	}
	if info.Size() < position.Offset {
		position.Offset = 0
	}
	position.Device = device
	position.Inode = inode
	if _, err := f.Seek(position.Offset, io.SeekStart); err != nil {
		return nil, position, err
	}
	reader := bufio.NewReaderSize(f, 64<<10)
	events := make([]model.SecurityEvent, 0, limit)
	next := position
	for {
		line, readErr := reader.ReadBytes('\n')
		if errors.Is(readErr, io.EOF) {
			// ModSecurity may still be writing the final JSON record. Leave an
			// incomplete line uncommitted so the next cycle can retry it.
			break
		}
		if readErr != nil {
			return nil, position, readErr
		}
		lineEnd := next.Offset + int64(len(line))
		line = line[:len(line)-1]
		parsed := parseAuditLine(line)
		remaining := limit - len(events)
		if len(events) > 0 && len(parsed) > remaining {
			// A JSON line is the checkpoint unit. Retry the whole line in the
			// next batch instead of advancing past messages that did not fit.
			break
		}
		next.Offset = lineEnd
		events = append(events, parsed...)
		if len(events) >= limit {
			break
		}
	}
	return events, next, nil
}

func (a *AuditReader) Commit(position AuditPosition) error {
	raw, err := json.Marshal(position)
	if err != nil {
		return err
	}
	return atomicWrite(a.checkpointPath, append(raw, '\n'), 0o640)
}

func (a *AuditReader) checkpoint() AuditPosition {
	raw, err := os.ReadFile(a.checkpointPath)
	if err != nil {
		return AuditPosition{}
	}
	var position AuditPosition
	if json.Unmarshal(raw, &position) == nil && position.Offset >= 0 {
		return position
	}
	var legacyOffset int64
	if _, err := fmt.Sscan(strings.TrimSpace(string(raw)), &legacyOffset); err == nil && legacyOffset >= 0 {
		return AuditPosition{Offset: legacyOffset}
	}
	return AuditPosition{}
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
