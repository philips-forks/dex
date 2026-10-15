package authflow

import "path"

// inAllowedGroups reports whether any of the user's groups matches one of a
// client's AllowedGroups. An entry matches a group exactly, or as a
// path.Match glob pattern (e.g. "urn:iamr:*" for every HSP IAM role group), so
// a client can admit a whole group namespace without listing every group.
// Malformed patterns only ever match exactly.
func inAllowedGroups(given, allowed []string) bool {
	for _, group := range given {
		for _, pattern := range allowed {
			if group == pattern {
				return true
			}
			if ok, err := path.Match(pattern, group); err == nil && ok {
				return true
			}
		}
	}
	return false
}
