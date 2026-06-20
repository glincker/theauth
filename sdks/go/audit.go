package theauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// AuditResource provides access to the audit log.
type AuditResource struct {
	tp *transport
}

// Query retrieves audit log entries. Pass nil to return all entries.
func (r *AuditResource) Query(ctx context.Context, filters *AuditFilters) ([]AuditEntry, error) {
	result, err := r.QueryPaginated(ctx, filters)
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

// QueryPaginated retrieves audit log entries and includes the total count.
func (r *AuditResource) QueryPaginated(ctx context.Context, filters *AuditFilters) (*PaginatedAuditLogs, error) {
	params := auditFiltersToParams(filters)
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "GET", "/audit", nil, params, &raw); err != nil {
		return nil, err
	}
	data := unwrapAPIData(raw)

	// The API may return either a plain list or a { entries, total } object.
	if len(data) > 0 && data[0] == '[' {
		var entries []AuditEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("theauth: decode audit entries: %w", err)
		}
		return &PaginatedAuditLogs{Entries: entries}, nil
	}

	var paginated PaginatedAuditLogs
	if err := json.Unmarshal(data, &paginated); err != nil {
		return nil, fmt.Errorf("theauth: decode paginated audit: %w", err)
	}
	return &paginated, nil
}

// Export exports audit log data as a raw string.
// The format is controlled by ExportOptions.Format (JSON or CSV).
// Pass nil to use the default format (JSON).
func (r *AuditResource) Export(ctx context.Context, opts *ExportOptions) (string, error) {
	params := exportOptionsToParams(opts)
	return r.tp.doRaw(ctx, "GET", "/audit/export", params)
}

func auditFiltersToParams(f *AuditFilters) map[string]string {
	if f == nil {
		return nil
	}
	params := make(map[string]string)
	if f.AgentID != nil {
		params["agentId"] = *f.AgentID
	}
	if f.UserID != nil {
		params["userId"] = *f.UserID
	}
	if f.Since != nil {
		params["since"] = *f.Since
	}
	if f.Until != nil {
		params["until"] = *f.Until
	}
	if len(f.Actions) > 0 {
		params["actions"] = strings.Join(f.Actions, ",")
	}
	if f.Result != nil {
		params["result"] = string(*f.Result)
	}
	if f.Limit != nil {
		params["limit"] = strconv.Itoa(*f.Limit)
	}
	if f.Offset != nil {
		params["offset"] = strconv.Itoa(*f.Offset)
	}
	if len(params) == 0 {
		return nil
	}
	return params
}

func exportOptionsToParams(opts *ExportOptions) map[string]string {
	params := make(map[string]string)
	if opts == nil {
		params["format"] = string(ExportFormatJSON)
		return params
	}
	if opts.Format == "" {
		params["format"] = string(ExportFormatJSON)
	} else {
		params["format"] = string(opts.Format)
	}
	if opts.Since != nil {
		params["since"] = *opts.Since
	}
	if opts.Until != nil {
		params["until"] = *opts.Until
	}
	return params
}
