// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

// OidEntry describes one extension of the Privasys OID scheme. The table
// AllOids in oids_gen.go is generated from oids.json at the repository root.
type OidEntry struct {
	OID        string
	Name       string
	Label      string
	Category   string
	Reserved   bool
	AppDefined bool
}
