package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rdleal/intervalst/interval"
	"github.com/yl2chen/cidranger"
	"gopkg.in/yaml.v3"

	ftp "github.com/jlaffaye/ftp"
	log "github.com/sirupsen/logrus"
)

var (
	AppVersion = "RRFusion 0.0.1a"

	ConfigFile = flag.String("config", "./conf/default.yaml", "Configuration file")
	Version    = flag.Bool("version", false, "Print version")
)

type Config struct {
	LogLevel  string `yaml:"logLevel"`
	Overwrite bool   `yaml:"overwrite"`
	LogFile   string `yaml:"logFile"`
	DBFile    string `yaml:"dbFile"`

	RPKI struct {
		Enabled  bool     `yaml:"enabled"`
		CacheDir string   `yaml:"cacheDir"`
		URLs     []string `yaml:"urls"`
	} `yaml:"rpki"`

	Delegated struct {
		Enabled  bool     `yaml:"enabled"`
		CacheDir string   `yaml:"cacheDir"`
		URLs     []string `yaml:"urls"`
	} `yaml:"delegated"`

	IRR struct {
		Enabled       bool     `yaml:"enabled"`
		CacheDir      string   `yaml:"cacheDir"`
		RpkiValid     bool     `yaml:"rpkiValid"`
		AsnFilter     bool     `yaml:"asnFilter"`
		PrefixFilter  bool     `yaml:"prefixFilter"`
		CountryFilter string   `yaml:"countryFilter"`
		DateFilter    int      `yaml:"dateFilter"`
		URLs          []string `yaml:"urls"`
	} `yaml:"irr"`

	VRO struct {
		Enabled      bool     `yaml:"enabled"`
		CacheDir     string   `yaml:"cacheDir"`
		RpkiValid    bool     `yaml:"rpkiValid"`
		AsnFilter    bool     `yaml:"asnFilter"`
		PrefixFilter bool     `yaml:"prefixFilter"`
		URLs         []string `yaml:"urls"`
	} `yaml:"vro"`
}

type ASNRecord struct {
	Status   string
	Registry string
	CC       string
}

type ROARecord struct {
	MaxLength int
	TA        string
	Expires   int
}

// 定义 prefixAssertion 数据结构
type PrefixAssertion struct {
	ASN             uint32 `json:"asn"`
	Prefix          string `json:"prefix"`
	MaxPrefixLength *int   `json:"maxPrefixLength,omitempty"`
	Comment         string `json:"comment"`
}

// Define DBFile data structure
type CustomDBFile struct {
	SlurmVersion           int `json:"slurmVersion"`
	LocallyAddedAssertions struct {
		PrefixAssertions []PrefixAssertion `json:"prefixAssertions"`
	} `json:"locallyAddedAssertions"`
}

type ROAMap map[string]struct {
	ASN     string
	ROAInfo map[string]string
}

// custom structure that conforms to RangerEntry interface
type RoaRangerEntry struct {
	ipNet  net.IPNet
	roaMap map[uint32][]ROARecord
}

func (b *RoaRangerEntry) Network() net.IPNet {
	return b.ipNet
}

func (b *RoaRangerEntry) NetworkStr() string {
	return b.ipNet.String()
}

// create customRangerEntry object using net and asn
func newRoaRangerEntry(ipNet net.IPNet, roa map[uint32][]ROARecord) cidranger.RangerEntry {
	return &RoaRangerEntry{
		ipNet:  ipNet,
		roaMap: roa,
	}
}

type IpRangerEntry struct {
	ipNet net.IPNet
	ipMap map[string]interface{}
}

func (b *IpRangerEntry) Network() net.IPNet {
	return b.ipNet
}

func (b *IpRangerEntry) NetworkStr() string {
	return b.ipNet.String()
}

// create customRangerEntry object using net and asn
func newIpRangerEntry(ipNet net.IPNet, data map[string]interface{}) cidranger.RangerEntry {
	return &IpRangerEntry{
		ipNet: ipNet,
		ipMap: data,
	}
}

type Validator struct {
	ROA cidranger.Ranger
	ASN interval.SearchTree[ASNRecord, uint32]
	IP  cidranger.Ranger
}

type ROV struct {
	config    Config
	validator Validator
}

func NewROV(config Config) *ROV {

	cmpFn := func(x, y uint32) int {
		if x < y {
			return -1
		} else if x > y {
			return 1
		}
		return 0
	}

	return &ROV{
		config: config,
		validator: Validator{
			ROA: cidranger.NewPCTrieRanger(),
			ASN: *interval.NewSearchTree[ASNRecord, uint32](cmpFn),
			IP:  cidranger.NewPCTrieRanger(),
		},
	}
}

// findUpdatedDate takes a map containing date strings and returns the most recent date.
// It extracts dates from the "last-modified" and "changed" entries, parses them,
// and returns the later of the two parsed dates. If parsing fails, it defaults to a predefined date.
func findUpdatedDate(rec map[string]string) time.Time {
	lastModified := rec["last-modified"]
	changed := rec["changed"]

	re1 := regexp.MustCompile(`(\d{8})$`)
	re2 := regexp.MustCompile(`(\d{4}-\d{2}-\d{2})`)

	var err error
	var date1 time.Time = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC) // Assign default value
	var date2 time.Time = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

	// attempt to parse date from "last-modified" entry
	if match1 := re1.FindStringSubmatch(lastModified); len(match1) > 0 {
		date1, err = time.Parse("20060102", match1[1])
		if err != nil {
			log.Warnf("parsing date1 error: %v, using default value: 1970-01-01", err)
		}
	}

	// attempt to parse date from "changed" entry
	if match2 := re2.FindStringSubmatch(changed); len(match2) > 0 {
		date2, err = time.Parse("2006-01-02", match2[1])
		if err != nil {
			log.Warnf("Error parsing date2: %v, using default value: 1970-01-01", err)
		}
	}

	// return the later of the two parsed dates
	if date1.After(date2) {
		return date1
	}
	return date2
}

// compareDateStr compares two date strings in the format "YYYYMMDD".
// It returns true if the current date is after the previous date,
// and handles parsing errors by logging them to the console.
func compareDateStr(curDateStr string, preDateStr string) bool {
	date1, err1 := time.Parse("20060102", curDateStr)
	date2, err2 := time.Parse("20060102", preDateStr)

	// Handle parsing errors
	if err1 != nil {
		log.Warn("Error parsing current date:", err1)
		return false
	}
	if err2 != nil {
		log.Warn("Error parsing previous date:", err2)
		return true // If the previous date is invalid, we can't compare
	}

	return date1.After(date2)
}

func downloadFTPFile(ftpServer, ftpFilePath, localPath string) error {

	// Ensure the FTP server has a port
	if !strings.Contains(ftpServer, ":") {
		ftpServer = fmt.Sprintf("%s:21", ftpServer) // Add default FTP port
	}

	// Establish a connection to the FTP server
	conn, err := ftp.Dial(ftpServer)
	if err != nil {
		return fmt.Errorf("failed to connect to FTP server: %w", err)
	}
	defer func() {
		if err := conn.Quit(); err != nil {
			log.Warnf("Error quitting FTP connection: %v", err)
		}
	}()

	// Login to the FTP server
	if err = conn.Login("anonymous", "anonymous@domain.com"); err != nil {
		return fmt.Errorf("failed to log in to FTP server: %w", err)
	}

	// Retrieve the file
	resp, err := conn.Retr(ftpFilePath)
	if err != nil {
		return fmt.Errorf("failed to retrieve file: %w", err)
	}
	defer resp.Close()

	// Create the local file
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer func() {
		if err := localFile.Close(); err != nil {
			log.Warnf("Error closing local file: %v", err)
		}
	}()

	// Copy the retrieved file to the local file
	if _, err = io.Copy(localFile, resp); err != nil {
		return fmt.Errorf("failed to write to local file: %w", err)
	}

	log.Infof("File downloaded successfully: %s\n", localPath)
	return nil
}

func downloadHTTPFile(httpURL, localPath string) error {
	// Fetch the file
	resp, err := http.Get(httpURL)
	if err != nil {
		return fmt.Errorf("failed to fetch the file: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch file: HTTP status %d", resp.StatusCode)
	}

	// Create the local file
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %v", err)
	}
	defer func() {
		if err := localFile.Close(); err != nil {
			log.Warnf("Error closing local file: %v", err)
		}
	}()

	// Copy the response body to the local file
	if _, err := io.Copy(localFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write file content: %v", err)
	}

	log.Infof("File downloaded successfully: %s\n", localPath)
	return nil
}

func downloadDatabase(localPath string, fileUrls []string, overwrite bool) error {
	if overwrite {
		if err := os.RemoveAll(localPath); err != nil {
			return fmt.Errorf("failed to remove existing directory %s: %w", localPath, err)
		}
	}

	if err := os.MkdirAll(localPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", localPath, err)
	}

	for _, fileUrl := range fileUrls {
		fileName := filepath.Base(fileUrl)
		localFilePath := filepath.Join(localPath, fileName)

		if !overwrite {
			if _, err := os.Stat(localFilePath); err == nil {
				continue // File already exists and overwrite is not enabled
			}
		}

		log.Infof("Downloading: %s\n", fileUrl)

		parsedURL, err := url.Parse(fileUrl)
		if err != nil {
			log.Errorf("Error parsing URL %s: %v\n", fileUrl, err)
			continue
		}

		var downloadErr error
		switch parsedURL.Scheme {
		case "ftp":
			downloadErr = downloadFTPFile(parsedURL.Host, parsedURL.Path, localFilePath)
		case "http", "https":
			downloadErr = downloadHTTPFile(fileUrl, localFilePath)
		default:
			log.Errorf("Unsupported protocol: %s\n", fileUrl)
			continue
		}

		if downloadErr != nil {
			log.Errorf("Error downloading %s: %v\n", fileUrl, downloadErr)
		}
	}
	return nil
}

func (rov *ROV) DownloadDatabases() {
	if rov.config.IRR.Enabled {
		if err := downloadDatabase(rov.config.IRR.CacheDir, rov.config.IRR.URLs, rov.config.Overwrite); err != nil {
			log.Errorf("Error downloading IRR database: %v\n", err)
		}
	}

	if rov.config.RPKI.Enabled {
		if err := downloadDatabase(rov.config.RPKI.CacheDir, rov.config.RPKI.URLs, rov.config.Overwrite); err != nil {
			log.Errorf("Error downloading RPKI database: %v\n", err)
		}
	}

	if rov.config.Delegated.Enabled {
		if err := downloadDatabase(rov.config.Delegated.CacheDir, rov.config.Delegated.URLs, rov.config.Overwrite); err != nil {
			log.Errorf("Error downloading delegated database: %v\n", err)
		}
	}

	if rov.config.VRO.Enabled {
		if err := downloadDatabase(rov.config.VRO.CacheDir, rov.config.VRO.URLs, rov.config.Overwrite); err != nil {
			log.Errorf("Error downloading VRO database: %v\n", err)
		}
	}
}

func (rov *ROV) loadRPKI() {
	log.Info("Loading RPKI data")
	for _, fileUrl := range rov.config.RPKI.URLs {
		log.Info("Loading RPKI data from:", fileUrl)
		parsedURL, err := url.Parse(fileUrl)
		if err != nil {
			log.Errorf("Error parsing URL: %v\n", err)
			continue
		}

		fileName := filepath.Base(parsedURL.Path)
		localFilePath := filepath.Join(rov.config.RPKI.CacheDir, fileName)

		file, err := os.ReadFile(localFilePath)
		if err != nil {
			log.Errorf("Error reading file %s: %v\n", localFilePath, err)
			continue
		}

		var data struct {
			ROAs []struct {
				ASN       any    `json:"asn"`
				Prefix    string `json:"prefix"`
				MaxLength int    `json:"maxLength"`
				TA        string `json:"ta"`
				Expires   int    `json:"expires"`
			} `json:"roas"`
		}
		if err := json.Unmarshal(file, &data); err != nil {
			log.Errorf("Error parsing JSON in %s: %v\n", localFilePath, err)
			continue
		}

		for _, roa := range data.ROAs {
			var asn uint32
			switch v := roa.ASN.(type) {
			case string:
				if strings.HasPrefix(v, "AS") {
					_, err := fmt.Sscanf(v[2:], "%d", &asn)
					if err != nil {
						log.Warnf("Failed to parse ASN from string %s: %v", v, err)
						continue
					}
				}
			case float64:
				asn = uint32(v)
			}

			// Parse the prefix and create a new entry if necessary
			_, network, _ := net.ParseCIDR(roa.Prefix)
			entry, _ := rov.validator.ROA.Remove(*network)

			roaMap := make(map[uint32][]ROARecord)
			if entry != nil {
				roaMap = entry.(*RoaRangerEntry).roaMap
			}

			roaMap[asn] = append(roaMap[asn], ROARecord{
				MaxLength: roa.MaxLength,
				TA:        roa.TA,
				Expires:   roa.Expires,
			})

			rov.validator.ROA.Insert(newRoaRangerEntry(*network, roaMap))
		}
	}
	log.Info("RPKI data loaded")
}

func (rov *ROV) loadDelegated() {
	log.Info("Loading delegated data")
	if !rov.config.Delegated.Enabled {
		log.Info("Delegated database not enabled")
		return
	}

	for _, fileUrl := range rov.config.Delegated.URLs {
		log.Info("Loading delegated data from:", fileUrl)
		parsedURL, err := url.Parse(fileUrl)
		if err != nil {
			log.Errorf("Error parsing URL: %v\n", err)
			continue
		}

		fileName := filepath.Base(parsedURL.Path)
		localFilePath := filepath.Join(rov.config.Delegated.CacheDir, fileName)

		file, err := os.Open(localFilePath)
		if err != nil {
			log.Errorf("Error reading file %s: %v\n", localFilePath, err)
			continue
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Warnf("Error closing file %s: %v", localFilePath, err)
			}
		}()

		scanner := bufio.NewScanner(file)
		previousRec := make(map[string]interface{})
		var startInterval map[string]interface{}

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			// Skip comments and empty lines
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}

			// Skip lines that don't contain valid data
			fieldsValue := strings.Split(line, "|")
			if len(fieldsValue) < 8 {
				log.Warnf("Invalid line format, skipping line: %s", line)
				continue
			}

			// Parse records into a map
			rec := map[string]interface{}{
				"registry": fieldsValue[0],
				"cc":       fieldsValue[1],
				"type":     fieldsValue[2],
				"start":    fieldsValue[3],
				"value":    fieldsValue[4],
				"date":     fieldsValue[5],
				"status":   fieldsValue[6],
			}

			if rec["value"], err = strconv.ParseUint(fieldsValue[4], 10, 32); err != nil {
				log.Errorf("Error converting value: %v", err)
				continue
			}

			// ASN records
			if rec["type"] == "asn" {
				rec["start"], err = strconv.ParseUint(fmt.Sprintf("%v", rec["start"]), 10, 32)
				if err != nil {
					log.Errorf("Error converting start: %v", err)
					continue
				}

				if startInterval == nil {
					startInterval = rec
				} else {
					if !(previousRec["registry"] == rec["registry"] &&
						previousRec["status"] == rec["status"] &&
						previousRec["cc"] == rec["cc"] &&
						(previousRec["start"].(uint64)+previousRec["value"].(uint64)) == rec["start"].(uint64)) {

						asnInfo := ASNRecord{
							Status:   previousRec["status"].(string),
							Registry: previousRec["registry"].(string),
							CC:       previousRec["cc"].(string),
						}

						rov.validator.ASN.Insert(uint32(startInterval["start"].(uint64)),
							uint32(previousRec["start"].(uint64)+previousRec["value"].(uint64)), asnInfo)
						startInterval = rec
					}

				}
				previousRec = rec

			} else if rec["type"] == "ipv4" || rec["type"] == "ipv6" {
				if previousRec["type"] == "asn" {
					// If the previous record was an ASN record, insert the previous interval
					if startInterval != nil {
						asnInfo := ASNRecord{
							Status:   previousRec["status"].(string),
							Registry: previousRec["registry"].(string),
							CC:       previousRec["cc"].(string),
						}
						rov.validator.ASN.Insert(uint32(startInterval["start"].(uint64)), uint32(previousRec["start"].(uint64)+previousRec["value"].(uint64)), asnInfo)
						startInterval = nil
					}
				}

				// Parse the prefix and create a new entry if necessary
				var prefixLen int
				if rec["type"] == "ipv4" {
					prefixLen = 32 - int(math.Log2(float64(rec["value"].(uint64))))
				} else {
					prefixLen = int(rec["value"].(uint64))
				}

				prefix := fmt.Sprintf("%v/%d", rec["start"], prefixLen)
				_, network, _ := net.ParseCIDR(prefix)

				// Search or create a new node for the prefix
				entry, _ := rov.validator.IP.Remove(*network)

				if entry != nil {
					log.Errorf("Duplicate prefix delegated record: %s\n in line: %s", prefix, line)
					ipMap := entry.(*IpRangerEntry).ipMap
					if compareDateStr(ipMap["date"].(string), rec["date"].(string)) {
						rov.validator.IP.Insert(newIpRangerEntry(*network, ipMap))
					} else {
						rov.validator.IP.Insert(newIpRangerEntry(*network, rec))
					}

				} else {
					rov.validator.IP.Insert(newIpRangerEntry(*network, rec))
				}
			} else {
				log.Errorf("Unknown type: %v\n in line: %s", rec["type"], line)
			}
		}

		if err := scanner.Err(); err != nil {
			log.Errorf("Error reading file %s: %v\n", localFilePath, err)
		}
	}
	log.Info("Delegated data loaded")
}

// checkDate checks if the targetDate is within a specified number of years from the current date.
// It returns 1 if the targetDate is within the range and 0 otherwise.
func (rov *ROV) checkDate(targetDate time.Time, year int) (status int) {

	if year <= 0 {
		log.Error("Invalid year value; must be positive")
		return -1 // Indicate an error for invalid input
	}

	duration := time.Since(targetDate) // Use time.Since for simplicity

	// Compare duration to the specified year in days
	if duration <= time.Duration(year*365*24)*time.Hour {
		return 1
	}

	return 0
}

// checkCountry checks if the country associated with a given ASN matches the target country.
// It returns 1 if they match, -1 if they do not, or 0 if the ASN information is not found.
func (rov *ROV) checkCountry(asn uint32, targetCountry string) (status int) {

	asnInfo, found := rov.validator.ASN.AnyIntersection(asn, asn)
	if !found {
		return 0 // ASN not found
	}

	if asnInfo.CC == targetCountry {
		return 1 // Country matches
	}

	return -1 // Country does not match
}

// checkASDelegated checks the status of the provided ASN (Autonomous System Number).
// It returns an integer status based on whether the ASN is found and its current status.
// Status return codes are:
// 0 - ASN not found,
// -1 - ASN status is reserved or available,
// 1 - ASN status is assigned.
func (rov *ROV) checkASDelegated(asn uint32) (status int) {
	asnInfo, found := rov.validator.ASN.AnyIntersection(asn, asn)
	if !found {
		return 0 // ASN not found
	}
	log.Debugf("Found ASN %d record: %v", asn, asnInfo)

	switch asnInfo.Status {
	case "reserved", "available":
		return -1 // Status is either reserved or available
	default:
		return 1 // Status is assigned
	}
}

// checkPrefix checks if the given CIDR prefix is valid and determines its status by examining the IP entries.
// It returns -1 for invalid or reserved/available status, 1 for valid status, and 0 if no entries are found.
func (rov *ROV) checkPrefix(prefix string) (status int) {
	// Get all the entries for the prefix
	netIp, targetNet, err := net.ParseCIDR(prefix)
	if err != nil {
		log.Errorf("Invalid CIDR format for prefix %s: %v", prefix, err)
		return -1
	}

	entries, err := rov.validator.IP.ContainingNetworks(netIp)
	if err != nil {
		log.Errorf("Error in ranger.ContainingNetworks(): %v", err)
		return -1
	}

	if len(entries) == 0 {
		return 0
	}

	targetMaskLen, _ := targetNet.Mask.Size() // Calculate target mask length once

	for _, e := range entries {
		entry, ok := e.(*IpRangerEntry)
		if !ok {
			continue
		}

		// Check if the target network is contained in the entry
		entryMaskLen, _ := entry.ipNet.Mask.Size()
		if entryMaskLen > targetMaskLen {
			continue
		}

		// Check Prefix status
		statusStr := entry.ipMap["status"].(string)
		if statusStr == "reserved" || statusStr == "available" {
			return -1 // If reserved or available, return -1
		}
		return 1 // If status is neither reserved nor available, return 1
	}
	return 0 // Default return if no conditions above met
}

// checkROA verifies if the given ASN has a valid Route Origin Authorization (ROA)
// for the specified prefix. It returns an integer status:
// 1 indicates a valid ROA found, 0 indicates no entries found,
// and -1 indicates an error or invalid ROA situation.
func (rov *ROV) checkROA(prefix string, asn uint32) (status int) {
	status = 0

	// Get all the entries for the prefix
	netIp, targetNet, err := net.ParseCIDR(prefix)
	if err != nil {
		log.Errorf("Invalid CIDR format for prefix %s: %v", prefix, err)
		return -1
	}

	entries, err := rov.validator.ROA.ContainingNetworks(netIp)
	if err != nil {
		log.Errorf("Error in ranger.ContainingNetworks(): %v", err)
		return -1
	}

	if len(entries) == 0 {
		return 0 // No entries found
	}

	targetMaskLen, _ := targetNet.Mask.Size() // Calculate target mask length once

	for _, e := range entries {
		entry, ok := e.(*RoaRangerEntry)
		if !ok {
			continue // Skip entries that are not of the expected type
		}

		// Check if the target network is contained in the entry
		entryMaskLen, _ := entry.ipNet.Mask.Size()
		if entryMaskLen > targetMaskLen {
			continue // Skip if entry mask length is greater than target mask length
		}

		// Check Roa MaxLength
		if roaItems, exists := entry.roaMap[asn]; exists {
			for _, roa := range roaItems {
				if roa.MaxLength >= targetMaskLen {
					return 1 // Found a valid ROA
				}
			}
		}
		status = -1 // Set status to invalid if no valid ROA found for ASN
	}
	return status
}

// checkROAForAses verifies if the given ASNs has a valid Route Origin Authorization (ROA)
// for the specified prefix. It returns an integer status:
// 1 indicates a valid ROA found, 0 indicates no entries found,
// and -1 indicates an error or invalid ROA situation.
func (rov *ROV) checkROAForAses(prefix string, asns []uint32) (status int) {
	status = 0

	// Get all the entries for the prefix
	netIp, targetNet, err := net.ParseCIDR(prefix)
	if err != nil {
		log.Errorf("Invalid CIDR format for prefix %s: %v", prefix, err)
		return -1
	}

	entries, err := rov.validator.ROA.ContainingNetworks(netIp)
	if err != nil {
		log.Errorf("Error in ranger.ContainingNetworks(): %v", err)
		return -1
	}

	if len(entries) == 0 {
		return 0 // No entries found
	}

	targetMaskLen, _ := targetNet.Mask.Size() // Calculate target mask length once

	for _, e := range entries {
		entry, ok := e.(*RoaRangerEntry)
		if !ok {
			continue // Skip entries that are not of the expected type
		}

		// Check if the target network is contained in the entry
		entryMaskLen, _ := entry.ipNet.Mask.Size()
		if entryMaskLen > targetMaskLen {
			continue // Skip if entry mask length is greater than target mask length
		}

		for _, asn := range asns {
			// Check Roa MaxLength
			if roaItems, exists := entry.roaMap[asn]; exists {
				for _, roa := range roaItems {
					if roa.MaxLength >= targetMaskLen {
						return 1
					}
				}
			}
		}

		status = -1 // Set status to invalid if no valid ROA found for ASN
	}
	return status
}

func (rov *ROV) extractVRORec(fileUrl string, ch chan<- PrefixAssertion, wg *sync.WaitGroup) {

	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Warnf("Panic in extractVRORec for %s: %v", fileUrl, r)
		}
	}()

	recNum := 0
	log.Infof("Extracting and validating route origin records from VRO file: %s", fileUrl)

	parsedURL, err := url.Parse(fileUrl)
	if err != nil {
		log.Errorf("Error parsing URL: %v\n", err)
		return
	}

	fileName := filepath.Base(parsedURL.Path)
	localFilePath := filepath.Join(rov.config.VRO.CacheDir, fileName)

	file, err := os.ReadFile(localFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", localFilePath, err)
		return
	}

	var data struct {
		SMGs []struct {
			Prefix string   `json:"prefix"`
			Asns   []uint32 `json:"asns"`
		} `json:"smg"`
	}

	if err := json.Unmarshal(file, &data); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON in %s: %v\n", localFilePath, err)
		return
	}

	for _, smg := range data.SMGs {
		status := 0

		if rov.config.VRO.PrefixFilter && rov.config.Delegated.Enabled {
			status = rov.checkPrefix(smg.Prefix)
		}

		// Check ROA and Prefix validity only if filters are enabled
		if status >= 0 && rov.config.VRO.RpkiValid && rov.config.RPKI.Enabled {
			status = rov.checkROAForAses(smg.Prefix, smg.Asns)
		}

		// Simplify AS delegation checks by combining them
		if status > 0 {
			for _, asn := range smg.Asns {

				var asnStatus int
				if rov.config.VRO.AsnFilter && rov.config.Delegated.Enabled {
					asnStatus = rov.checkASDelegated(asn)
				}

				if asnStatus >= 0 {
					// Send data to channel, ready for generation of the custom DB
					ch <- PrefixAssertion{
						ASN:     asn,
						Prefix:  smg.Prefix,
						Comment: "vro_" + fileName,
					}
					recNum++
				}
			}
		}
	}
	log.Infof("Processed %d records from VRO file %s", recNum, localFilePath)
}

func (rov *ROV) extractIRRRec(fileUrl string, ch chan<- PrefixAssertion, wg *sync.WaitGroup) {

	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Warnf("Panic in extractIRRRec for %s: %v", fileUrl, r)
		}
	}()

	recNum := 0

	log.Infof("Extracting and validating route origin records from IRR file: %s", fileUrl)
	parsedURL, err := url.Parse(fileUrl)
	if err != nil {
		log.Errorf("Error parsing URL: %v\n", err)
		return
	}

	fileName := filepath.Base(parsedURL.Path)
	localFilePath := filepath.Join(rov.config.IRR.CacheDir, fileName)

	file, err := os.Open(localFilePath)
	if err != nil {
		log.Errorf("Error opening file %s: %v\n", localFilePath, err)
		return
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		log.Errorf("Error decompressing file %s: %v\n", localFilePath, err)
		return
	}
	defer gzReader.Close()

	scanner := bufio.NewScanner(gzReader)
	// Set the buffer size to 512 KB
	const maxBufferSize = 512 * 1024 // 10 MB
	buf := make([]byte, maxBufferSize)
	scanner.Buffer(buf, maxBufferSize)

	rec := make(map[string]string)
	var field string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "%") {
			continue // Skip comments and headers
		}

		if line == "" {
			if route, ok := rec["route"]; ok {
				if origin, ok := rec["origin"]; ok {

					asn, err := strconv.ParseUint(strings.Split(origin[2:], "#")[0], 10, 32)
					if err != nil {
						log.Errorf("Error converting ASN in %s, invalid ASN format: %v\n", localFilePath, rec)
						rec = make(map[string]string) // Reset the record for the next entry
						continue
					}

					status := 0

					if rov.config.IRR.DateFilter > 0 {
						latestTime := findUpdatedDate(rec)
						status = rov.checkDate(latestTime, rov.config.IRR.DateFilter)
					}

					if status >= 0 && rov.config.IRR.CountryFilter != "" {
						status = rov.checkCountry(uint32(asn), rov.config.IRR.CountryFilter)
					}

					if status >= 0 && rov.config.IRR.RpkiValid && rov.config.RPKI.Enabled {
						status = rov.checkROA(route, uint32(asn))
					}

					if status >= 0 && rov.config.IRR.AsnFilter && rov.config.Delegated.Enabled {
						status = rov.checkASDelegated(uint32(asn))
					}

					if status >= 0 && rov.config.IRR.PrefixFilter && rov.config.Delegated.Enabled {
						status = rov.checkPrefix(route)
					}

					if status >= 0 {
						// Send data to channel
						ch <- PrefixAssertion{
							ASN:     uint32(asn),
							Prefix:  route,
							Comment: "irr_" + rec["source"],
						}
						recNum++
					}
				}
			}
			rec = make(map[string]string)
			field = ""
		} else {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				field = strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				if field == "route6" {
					field = "route"
				}

				rec[field] = value
			} else if field != "" && (field == "descr" || field == "addr") {
				rec[field] += "\n" + line
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading file %s: %v\n", localFilePath, err)
	}

	log.Infof("Processed %d records from IRR file %s", recNum, localFilePath)
}

func (rov *ROV) saveCustomDB(ch <-chan PrefixAssertion, done chan<- struct{}) {

	// Open the custom DB file
	file, err := os.Create(rov.config.DBFile)
	if err != nil {
		log.Errorf("Error creating output file: %v\n", err)
		done <- struct{}{}
		return
	}
	defer file.Close()

	// Initialize the Database data structure
	slurm := CustomDBFile{
		SlurmVersion: 2,
	}
	slurm.LocallyAddedAssertions.PrefixAssertions = make([]PrefixAssertion, 0)

	// Wait for the channel to be closed
	for assertion := range ch {
		slurm.LocallyAddedAssertions.PrefixAssertions = append(slurm.LocallyAddedAssertions.PrefixAssertions, assertion)
	}

	log.Info("Saving custom DB file...")

	// Write the JSON data to the file
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Set the JSON indentation to 2 spaces
	err = encoder.Encode(slurm)
	if err != nil {
		log.Errorf("Error encoding JSON: %v\n", err)
	}

	done <- struct{}{}
}

func (rov *ROV) GenCustomDB() {
	if rov.config.RPKI.Enabled {
		rov.loadRPKI()
	}

	if rov.config.Delegated.Enabled {
		rov.loadDelegated()
	}

	// Create a channel for the producer/consumer pattern
	ch := make(chan PrefixAssertion, 1000) // buffer size
	var wg sync.WaitGroup

	// Start the producer(s)
	if rov.config.IRR.Enabled {
		for _, fileUrl := range rov.config.IRR.URLs {
			wg.Add(1)
			go rov.extractIRRRec(fileUrl, ch, &wg)
		}
	}

	if rov.config.VRO.Enabled {
		for _, fileUrl := range rov.config.VRO.URLs {
			wg.Add(1)
			go rov.extractVRORec(fileUrl, ch, &wg)
		}
	}

	// Start the consumer(s)
	done := make(chan struct{})
	go rov.saveCustomDB(ch, done)

	// Wait for the producers to finish
	wg.Wait()
	close(ch)

	// Wait for the consumer to finish
	<-done

	log.Info("Custom DB generation complete.")
}

func main() {
	flag.Parse()

	// Check for illegal positional arguments
	if flag.NArg() > 0 {
		fmt.Printf("%s: illegal positional argument(s) provided (\"%s\") - did you mean to provide a flag?\n", os.Args[0], strings.Join(flag.Args(), " "))
		os.Exit(2)
	}

	// Handle version flag
	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	// Open the configuration file
	file, err := os.Open(*ConfigFile)
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer file.Close()

	// Decode the configuration
	var config Config
	if err := yaml.NewDecoder(file).Decode(&config); err != nil {
		log.Fatalf("Failed to decode config: %v", err)
	}

	// Set the log level
	if lvl, err := log.ParseLevel(config.LogLevel); err == nil {
		log.SetLevel(lvl)
	} else {
		log.Warnf("Invalid log level specified, using default: %v", err)
		log.SetLevel(log.InfoLevel) // Set a default log level if there's an error
	}

	// Open the log file
	logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close() // Ensure the log file gets closed

	log.SetOutput(logFile)
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
	})

	rov := NewROV(config)

	// Download databases and generate the custom DB
	rov.DownloadDatabases()
	rov.GenCustomDB()
}
