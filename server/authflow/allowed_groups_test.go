package authflow

import "testing"

func TestInAllowedGroups(t *testing.T) {
	for _, tc := range []struct {
		name    string
		given   []string
		allowed []string
		want    bool
	}{
		{name: "exact match", given: []string{"a", "philips-internal"}, allowed: []string{"philips-internal"}, want: true},
		{name: "no match", given: []string{"philips-internal:x"}, allowed: []string{"philips-internal"}, want: false},
		{name: "no groups", given: nil, allowed: []string{"urn:iamr:*"}, want: false},
		{name: "wildcard suffix", given: []string{"urn:iamr:8a67a785-73bb:ADMIN"}, allowed: []string{"urn:iamr:*"}, want: true},
		{name: "wildcard does not match other prefix", given: []string{"philips-internal"}, allowed: []string{"urn:iamr:*"}, want: false},
		{name: "wildcard in the middle", given: []string{"urn:iamr:org1:ADMIN"}, allowed: []string{"urn:iamr:*:ADMIN"}, want: true},
		{name: "wildcard in the middle, other role", given: []string{"urn:iamr:org1:USER"}, allowed: []string{"urn:iamr:*:ADMIN"}, want: false},
		{name: "any of several patterns", given: []string{"urn:iamr:org1:USER"}, allowed: []string{"philips-internal", "urn:iamr:*"}, want: true},
		{name: "exact match wins even for glob characters", given: []string{"team[1]"}, allowed: []string{"team[1]"}, want: true},
		{name: "malformed pattern only matches exactly", given: []string{"x"}, allowed: []string{"["}, want: false},
		{name: "? matches a single character", given: []string{"ab"}, allowed: []string{"a?"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := inAllowedGroups(tc.given, tc.allowed); got != tc.want {
				t.Errorf("inAllowedGroups(%q, %q) = %v, want %v", tc.given, tc.allowed, got, tc.want)
			}
		})
	}
}
