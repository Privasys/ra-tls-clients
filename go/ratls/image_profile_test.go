package ratls

import "testing"

func TestVerifyImageProfile(t *testing.T) {
	prod := []OidExtension{{OID: OidImageProfile, Value: []byte("production\n")}}
	dev := []OidExtension{{OID: OidImageProfile, Value: []byte("dev")}}
	unknown := []OidExtension{{OID: OidImageProfile, Value: []byte("debug-custom")}}
	legacy := []OidExtension{{OID: OidDEKOrigin, Value: []byte("generated")}}

	cases := []struct {
		name    string
		exts    []OidExtension
		allow   bool
		wantErr bool
	}{
		{"production accepted by default", prod, false, false},
		{"production accepted when debug allowed", prod, true, false},
		{"dev rejected by default", dev, false, true},
		{"dev accepted when opted in", dev, true, false},
		{"unknown profile rejected by default (fail closed)", unknown, false, true},
		{"unknown profile accepted when opted in", unknown, true, false},
		{"missing extension accepted (legacy images)", legacy, false, false},
		{"no extensions accepted (legacy images)", nil, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyImageProfile(tc.exts, &VerificationPolicy{AllowDebugImages: tc.allow})
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
