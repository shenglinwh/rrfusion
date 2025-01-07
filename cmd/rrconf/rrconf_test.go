package main

import (
	"net"
	"testing"
	"time"

	"github.com/rdleal/intervalst/interval"
	"github.com/stretchr/testify/assert"
	"github.com/yl2chen/cidranger"
)

func TestCheckDate(t *testing.T) {
	rov := &ROV{}

	t.Run("Happy Path - within range", func(t *testing.T) {
		targetDate := time.Now().AddDate(-1, 0, 2) // < 1 year ago
		year := 1
		result := rov.checkDate(targetDate, year)
		assert.Equal(t, 1, result)
	})

	t.Run("Happy Path - exactly one year", func(t *testing.T) {
		targetDate := time.Now().AddDate(-1, 0, -1) // 1 year ago
		year := 1
		result := rov.checkDate(targetDate, year)
		assert.Equal(t, 0, result)
	})

	t.Run("Edge Case - negative year", func(t *testing.T) {
		targetDate := time.Now()
		year := -1
		result := rov.checkDate(targetDate, year)
		if result != -1 {
			t.Errorf("Expected status -1 for invalid year, got %d", result)
		}
	})

	t.Run("Edge Case - zero year", func(t *testing.T) {
		targetDate := time.Now()
		year := 0
		result := rov.checkDate(targetDate, year)
		assert.Equal(t, -1, result)
	})

	t.Run("Edge Case - far in the past", func(t *testing.T) {
		targetDate := time.Now().AddDate(-5, 0, 0) // 5 years ago
		year := 1
		result := rov.checkDate(targetDate, year)
		assert.Equal(t, 0, result)
	})
}

func TestCheckCountry(t *testing.T) {
	// notice：there is a bug about the interval [a, b) in intervalst package
	// So we need to change the function intersects in interval.go to make it work
	// func (it interval[V, T]) intersects(start, end T, cmp CmpFunc[T]) bool {
	// 	return cmp.lte(it.Start, end) && cmp.lte(start, it.End)  && cmp.lt(end, it.End)
	// }
	rov := &ROV{
		validator: Validator{
			ASN: *interval.NewSearchTree[ASNRecord, uint32](func(x, y uint32) int {
				if x < y {
					return -1
				} else if x > y {
					return 1
				}
				return 0
			}),
		},
	}

	// Happy path: ASN found and country matches
	rov.validator.ASN.Insert(1, 2, ASNRecord{CC: "US"})
	rov.validator.ASN.Insert(2, 3, ASNRecord{CC: "CN"})
	rov.validator.ASN.Insert(3, 23456, ASNRecord{CC: "CA"})

	tests := []struct {
		asn           uint32
		targetCountry string
		expected      int
	}{
		{1, "US", 1},     // Happy path: ASN found and country matches
		{1, "CA", 0},     // Happy path: ASN found but country does not match
		{2, "CN", 1},     // Happy path: ASN found and country matches
		{3, "CA", 1},     // Happy path: ASN found and country matches
		{3, "CN", 0},     // Happy path: ASN found and country does not match
		{4, "US", 0},     // Happy path: ASN found but country does not match
		{23456, "CA", 0}, // Edge case: ASN not found
	}

	for _, test := range tests {
		result := rov.checkCountry(test.asn, test.targetCountry)
		assert.Equal(t, test.expected, result)
	}
}

func TestFindUpdatedDate(t *testing.T) {
	tests := []struct {
		input  map[string]string
		output time.Time
	}{
		{
			input: map[string]string{
				"last-modified": "20230101",
				"changed":       "2023-01-02",
			},
			output: time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			input: map[string]string{
				"last-modified": "20230101",
				"changed":       "2023-01-01",
			},
			output: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			input: map[string]string{
				"last-modified": "20230101",
				"changed":       "invalid-date",
			},
			output: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			input: map[string]string{
				"last-modified": "invalid-date",
				"changed":       "2023-01-02",
			},
			output: time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			input: map[string]string{
				"last-modified": "invalid-date",
				"changed":       "invalid-date",
			},
			output: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, test := range tests {
		result := findUpdatedDate(test.input)
		assert.Equal(t, test.output, result)
	}
}

func TestCompareDateStr(t *testing.T) {
	tests := []struct {
		curDateStr  string
		preDateStr  string
		expected    bool
		description string
	}{
		{"20231010", "20231009", true, "Cur date is after pre date"},
		{"20231009", "20231010", false, "Cur date is before pre date"},
		{"20231010", "20231010", false, "Cur date is the same as pre date"},
		{"invalid_date", "20231010", false, "Current date is invalid"},
		{"20231010", "invalid_date", true, "Previous date is invalid"},
		{"20231010", "2022-10-10", true, "Current date format is valid but previous date format is incorrect"},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			got := compareDateStr(test.curDateStr, test.preDateStr)
			assert.Equal(t, test.expected, got, test.description)
		})
	}
}

func TestCheckASDelegated(t *testing.T) {
	rov := &ROV{
		validator: Validator{
			ASN: *interval.NewSearchTree[ASNRecord, uint32](func(x, y uint32) int {
				if x < y {
					return -1
				} else if x > y {
					return 1
				}
				return 0
			}),
		},
	}

	// Test case 1: ASN not found
	status := rov.checkASDelegated(100)
	assert.Equal(t, 0, status, "Expected status for not found ASN to be 0")

	// Test case 2: ASN is reserved
	rov.validator.ASN.Insert(100, 200, ASNRecord{Status: "reserved", Registry: "example", CC: "US"})
	status = rov.checkASDelegated(100)
	assert.Equal(t, -1, status, "Expected status for reserved ASN to be -1")

	// Test case 3: ASN is available
	rov.validator.ASN.Insert(200, 300, ASNRecord{Status: "available", Registry: "example", CC: "US"})
	status = rov.checkASDelegated(200)
	assert.Equal(t, -1, status, "Expected status for available ASN to be -1")

	// Test case 4: ASN is assigned
	rov.validator.ASN.Insert(300, 400, ASNRecord{Status: "assigned", Registry: "example", CC: "US"})
	status = rov.checkASDelegated(300)
	assert.Equal(t, 1, status, "Expected status for assigned ASN to be 1")
	status = rov.checkASDelegated(350)
	assert.Equal(t, 1, status, "Expected status for assigned ASN to be 1")
	status = rov.checkASDelegated(400)
	assert.Equal(t, 0, status, "Expected status for end asn of interval to be 0")
}

func TestCheckPrefix(t *testing.T) {
	// Mock Data
	rov := &ROV{
		validator: Validator{
			IP: cidranger.NewPCTrieRanger(),
		},
	}

	// Test case 1: Valid prefix with valid status
	ipNet1 := net.IPNet{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(24, 32)}
	rov.validator.IP.Insert(newIpRangerEntry(ipNet1, map[string]interface{}{"status": "assigned"}))

	status := rov.checkPrefix("192.0.2.0/24")
	assert.Equal(t, 1, status)

	// Test case 2: Valid prefix with reserved status
	ipNet2 := net.IPNet{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(24, 32)}
	rov.validator.IP.Insert(newIpRangerEntry(ipNet2, map[string]interface{}{"status": "reserved"}))

	status = rov.checkPrefix("192.0.2.0/24")
	assert.Equal(t, -1, status)

	// Test case 3: Valid prefix with available status
	ipNet3 := net.IPNet{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(24, 32)}
	rov.validator.IP.Insert(newIpRangerEntry(ipNet3, map[string]interface{}{"status": "available"}))

	status = rov.checkPrefix("192.0.2.0/24")
	assert.Equal(t, -1, status)

	// Test case 4: Prefix not found
	status = rov.checkPrefix("203.0.113.0/24")
	assert.Equal(t, 0, status)

	// Test case 5: Invalid CIDR format
	status = rov.checkPrefix("invalid-cidr")
	assert.Equal(t, -1, status)
}

func TestCheckROA(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		asn      uint32
		expected int
		setup    func(*ROV)
	}{
		{
			name:     "Valid ROA found",
			prefix:   "192.0.2.0/24",
			asn:      65000,
			expected: 1,
			setup: func(rov *ROV) {
				// Setup valid ROA for the ASN
				roaMap := map[uint32][]ROARecord{
					65000: {
						{MaxLength: 24, TA: "test", Expires: 0},
					},
				}
				_, network, _ := net.ParseCIDR("192.0.2.0/24")
				entry := newRoaRangerEntry(*network, roaMap)
				rov.validator.ROA.Insert(entry)
			},
		},
		{
			name:     "Valid ROA found",
			prefix:   "192.0.2.0/24",
			asn:      65000,
			expected: 1,
			setup: func(rov *ROV) {
				// Setup valid ROA for the ASN
				roaMap := map[uint32][]ROARecord{
					65000: {
						{MaxLength: 24, TA: "test", Expires: 0},
					},
				}
				_, network, _ := net.ParseCIDR("192.0.2.0/23")
				entry := newRoaRangerEntry(*network, roaMap)
				rov.validator.ROA.Insert(entry)
			},
		},
		{
			name:     "Valid ROA not found",
			prefix:   "192.0.2.0/24",
			asn:      65000,
			expected: 0,
			setup: func(rov *ROV) {
				// Setup valid ROA for the ASN
				roaMap := map[uint32][]ROARecord{
					65000: {
						{MaxLength: 26, TA: "test", Expires: 0},
					},
				}
				_, network, _ := net.ParseCIDR("192.0.2.0/25")
				entry := newRoaRangerEntry(*network, roaMap)
				rov.validator.ROA.Insert(entry)
			},
		},
		{
			name:     "No entries found",
			prefix:   "192.0.2.0/24",
			asn:      65000,
			expected: 0,
			setup: func(rov *ROV) {
				// No ROA entries setup
			},
		},
		{
			name:     "Invalid CIDR format",
			prefix:   "invalidCIDR",
			asn:      65000,
			expected: -1,
			setup: func(rov *ROV) {
				// No specific setup needed
			},
		},
		{
			name:     "ROA not found for ASN",
			prefix:   "192.0.2.0/24",
			asn:      65001,
			expected: -1,
			setup: func(rov *ROV) {
				// Setup valid ROA for a different ASN
				roaMap := map[uint32][]ROARecord{
					65000: {
						{MaxLength: 24, TA: "test", Expires: 0},
					},
				}
				_, network, _ := net.ParseCIDR("192.0.2.0/24")
				entry := newRoaRangerEntry(*network, roaMap)
				rov.validator.ROA.Insert(entry)
			},
		},
		{
			name:     "Roa  maxlength greater than target",
			prefix:   "192.0.2.0/25",
			asn:      65000,
			expected: 1,
			setup: func(rov *ROV) {
				// Setup ROA with a larger mask length
				roaMap := map[uint32][]ROARecord{
					65000: {
						{MaxLength: 26, TA: "test", Expires: 0},
					},
				}
				_, network, _ := net.ParseCIDR("192.0.2.0/24")
				entry := newRoaRangerEntry(*network, roaMap)
				rov.validator.ROA.Insert(entry)
			},
		},
		{
			name:     "Roa maxlength less than target",
			prefix:   "192.0.2.0/26",
			asn:      65000,
			expected: -1,
			setup: func(rov *ROV) {
				// Setup ROA with a larger mask length
				roaMap := map[uint32][]ROARecord{
					65000: {
						{MaxLength: 25, TA: "test", Expires: 0},
					},
				}
				_, network, _ := net.ParseCIDR("192.0.2.0/24")
				entry := newRoaRangerEntry(*network, roaMap)
				rov.validator.ROA.Insert(entry)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup ROV with a Validator
			rov := &ROV{
				validator: Validator{
					ROA: cidranger.NewPCTrieRanger(),
				},
			}
			tt.setup(rov)

			// Call checkROA
			status := rov.checkROA(tt.prefix, tt.asn)

			// Assert the expected result
			assert.Equal(t, tt.expected, status)
		})
	}
}

func TestCheckROAForAses(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		asns     []uint32
		expected int
	}{
		{
			name:     "Valid ROA found",
			prefix:   "192.168.1.0/24",
			asns:     []uint32{65000},
			expected: 1,
		},
		{
			name:     "Valid ROA found",
			prefix:   "192.168.1.0/24",
			asns:     []uint32{65000, 65001, 65002},
			expected: 1,
		},
		{
			name:     "No entries found",
			prefix:   "10.0.0.0/8",
			asns:     []uint32{65001, 65002},
			expected: 0,
		},
		{
			name:     "Invalid CIDR format",
			prefix:   "invalid-cidr",
			asns:     []uint32{65002, 65007},
			expected: -1,
		},
		{
			name:     "ROA not found",
			prefix:   "192.0.2.0/24",
			asns:     []uint32{65003, 65004},
			expected: 0,
		},
		{
			name:     "ROA found with MaxLength check",
			prefix:   "192.168.1.0/25",
			asns:     []uint32{65001, 65000},
			expected: 1,
		},
		{
			name:     "ASN not available in ROA",
			prefix:   "192.168.1.0/24",
			asns:     []uint32{65001},
			expected: -1,
		},
	}

	rov := &ROV{
		validator: Validator{
			ROA: cidranger.NewPCTrieRanger(),
		},
	}

	// Setup mock data
	roaMap := make(map[uint32][]ROARecord)
	roaMap[65000] = []ROARecord{
		{MaxLength: 25, TA: "test", Expires: 0},
	}
	rov.validator.ROA.Insert(newRoaRangerEntry(net.IPNet{IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(24, 32)}, roaMap))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rov.checkROAForAses(tt.prefix, tt.asns)

			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}
