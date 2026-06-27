package audit

import (
	"strings"
	"testing"
	"time"
)

func TestEventPartition(t *testing.T) {
	full := Event{
		Action: ActionToolCall, Outcome: OutcomeDenied, ReasonCode: "forbidden",
		Tool: "delete_record", Subject: "sub-1", Issuer: "iss", Audience: "aud",
		Scopes: []string{"a", "b"}, Email: "p@hi.test", Time: time.Unix(1, 0),
	}
	tests := []struct {
		name         string
		got          []Attr
		wantKeys     []string // exact set, in order
		forbiddenKey []string // keys that must NOT appear
	}{
		{
			name:         "metric labels are bounded and non-PII",
			got:          full.MetricLabels(),
			wantKeys:     []string{"action", "outcome", "reason_code"},
			forbiddenKey: []string{"tool", "subject", "issuer", "audience", "scopes", "email"},
		},
		{
			name:         "trace attributes add PHI-safe fields, never email",
			got:          full.TraceAttributes(),
			wantKeys:     []string{"action", "outcome", "reason_code", "tool", "subject", "issuer", "audience", "scopes"},
			forbiddenKey: []string{"email"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := make([]string, len(tt.got))
			for i, a := range tt.got {
				keys[i] = a.Key
			}
			if strings.Join(keys, ",") != strings.Join(tt.wantKeys, ",") {
				t.Errorf("keys = %v, want %v", keys, tt.wantKeys)
			}
			for _, a := range tt.got {
				if a.Value == full.Email {
					t.Errorf("PII Email leaked as %s=%q", a.Key, a.Value)
				}
				for _, bad := range tt.forbiddenKey {
					if a.Key == bad {
						t.Errorf("forbidden key %q present", bad)
					}
				}
			}
		})
	}
}

func TestMetricLabelsOmitsEmptyReasonCode(t *testing.T) {
	granted := Event{Action: ActionTokenExchange, Outcome: OutcomeGranted}
	for _, a := range granted.MetricLabels() {
		if a.Key == "reason_code" {
			t.Fatalf("granted event must omit reason_code label, got %q", a.Value)
		}
	}
}
