// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import "testing"

func TestTCBStatusAcceptable(t *testing.T) {
	cases := []struct {
		name       string
		status     TCBStatus
		acceptable []TCBStatus
		wantOK     bool
	}{
		{"empty status accepted (server didn't report)", "", nil, true},
		{"UpToDate floor", TCBUpToDate, nil, true},
		{"SWHardeningNeeded floor", TCBSWHardeningNeeded, nil, true},
		{"OutOfDate rejected by floor", TCBOutOfDate, nil, false},
		{"ConfigAndSWHardening rejected by floor", TCBConfigurationAndSWHardeningNeeded, nil, false},
		{"ConfigAndSWHardening accepted when relaxed", TCBConfigurationAndSWHardeningNeeded, []TCBStatus{TCBConfigurationAndSWHardeningNeeded}, true},
		{"relaxing one status doesn't accept another", TCBConfigurationNeeded, []TCBStatus{TCBOutOfDate}, false},
		{"Revoked never accepted even if listed", TCBRevoked, []TCBStatus{TCBRevoked}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tcbStatusAcceptable(tc.status, tc.acceptable)
			if tc.wantOK && err != nil {
				t.Fatalf("expected acceptable, got error: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("expected rejection for status %q, got nil", tc.status)
			}
		})
	}
}
