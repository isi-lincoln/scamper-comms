package objects

import (
	"net"
	"time"
)

/* LLM Generated */
// scamper objects

type Tx struct {
	Sec   int    `json:"sec"`
	Usec  int    `json:"usec"`
	Ftime string `json:"ftime,omitempty"`
}

type MPLSLabel struct {
	MPLSTTL   int `json:"mpls_ttl"`
	MPLSS     int `json:"mpls_s"`
	MPLSEXP   int `json:"mpls_exp"`
	MPLSLabel int `json:"mpls_label"`
}

type ICMPExt struct {
	IECN       int         `json:"ie_cn"`
	IECT       int         `json:"ie_ct"`
	IEDL       int         `json:"ie_dl"`
	MPLSLabels []MPLSLabel `json:"mpls_labels"`
}

type ScamperHop struct {
	Addr      string    `json:"addr"`
	ProbeTTL  int       `json:"probe_ttl"`
	ProbeID   int       `json:"probe_id"`
	ProbeSize int       `json:"probe_size"`
	Tx        Tx        `json:"tx"`
	RTT       float64   `json:"rtt"`
	ReplyTTL  int       `json:"reply_ttl"`
	ReplyTOS  int       `json:"reply_tos"`
	ReplyIPID int       `json:"reply_ipid"`
	ReplySize int       `json:"reply_size"`
	ICMPType  int       `json:"icmp_type"`
	ICMPCode  int       `json:"icmp_code"`
	ICMPQTTL  int       `json:"icmp_q_ttl"`
	ICMPQIPL  int       `json:"icmp_q_ipl"`
	ICMPQTOS  int       `json:"icmp_q_tos"`
	ICMPExts  []ICMPExt `json:"icmpext,omitempty"`
}

type Trace struct {
	Type       string       `json:"type"`
	Version    string       `json:"version"`
	UserID     int          `json:"userid"`
	Method     string       `json:"method"`
	Src        string       `json:"src"`
	Dst        string       `json:"dst"`
	Sport      int          `json:"sport"`
	Dport      int          `json:"dport"`
	StopReason string       `json:"stop_reason"`
	StopData   int          `json:"stop_data"`
	Start      Tx           `json:"start"`
	HopCount   int          `json:"hop_count"`
	Attempts   int          `json:"attempts"`
	HopLimit   int          `json:"hoplimit"`
	FirstHop   int          `json:"firsthop"`
	Wait       int          `json:"wait"`
	WaitProbe  int          `json:"wait_probe"`
	TOS        int          `json:"tos"`
	ProbeSize  int          `json:"probe_size"`
	ProbeCount int          `json:"probe_count"`
	Hops       []ScamperHop `json:"hops"`
}

type Root struct {
	Data Trace `json:"data"`
}

/* fin */

// pathfinder objects

// Country represents a country with threat level (updated)
type Country struct {
	ISO    string  `json:"iso"`
	ISO3   *string `json:"iso3,omitempty"`
	Name   *string `json:"name,omitempty"`
	Threat *int    `json:"threat,omitempty"`
	Method *string `json:"method,omitempty"`
}

// Group represents a group with optional threat level
type Group struct {
	Name   string `json:"name"`
	Threat *int   `json:"threat,omitempty"`
}

// CountryGroup represents the many-to-many relationship between countries and groups
type CountryGroup struct {
	Country string `json:"country"`
	Group   string `json:"group"`
}

// ASN represents an Autonomous System Number (updated for response)
type ASN struct {
	ASN     int64    `json:"asn"`
	Name    *string  `json:"name,omitempty"`
	Country *Country `json:"country,omitempty"`
	Threat  *int     `json:"threat,omitempty"`
	Method  *string  `json:"method,omitempty"`
}

// Vendor represents a vendor/organization (updated for response)
type Vendor struct {
	ID      int64    `json:"id"`
	Name    *string  `json:"name,omitempty"`
	Country *Country `json:"country,omitempty"`
	Threat  *int     `json:"threat,omitempty"`
	Method  *string  `json:"method,omitempty"`
}

// IPBlock represents an IP address block
type IPBlock struct {
	Start         net.IP  `json:"start"`
	End           net.IP  `json:"end"`
	ASN           *int64  `json:"asn,omitempty"`
	ASNMethod     *string `json:"asn_method,omitempty"`
	Country       *string `json:"country,omitempty"`
	CountryMethod *string `json:"country_method,omitempty"`
	Name          *string `json:"name,omitempty"`
	NameMethod    *string `json:"name_method,omitempty"`
}

// Monitor represents a monitoring point (simplified for response)
type Monitor struct {
	ID string `json:"id"`
}

// VantagePoint represents a network vantage point
type VantagePoint struct {
	ID         int           `json:"id"`
	IP         *net.IP       `json:"ip,omitempty"`
	ASN        *int64        `json:"asn,omitempty"`
	City       *string       `json:"city,omitempty"`
	Region     *string       `json:"region,omitempty"`
	ISO        *string       `json:"iso,omitempty"`
	Latitude   *float64      `json:"latitude,omitempty"`
	Longitude  *float64      `json:"longitude,omitempty"`
	Country    *Country      `json:"country,omitempty"`
	Threat     *int          `json:"threat,omitempty"`
	Method     *string       `json:"method,omitempty"`
	Annotation *IPAnnotation `json:"annotation,omitempty"`
}

// TraceNode represents a node in a traceroute
type TraceNode struct {
	ID       int     `json:"id"`
	IP       net.IP  `json:"ip"`
	Hostname *string `json:"hostname,omitempty"`
	ASN      *int    `json:"asn,omitempty"`
	OrgName  *string `json:"org_name,omitempty"`
	Country  *string `json:"country,omitempty"`
	VP       *int    `json:"vp,omitempty"`
}

// TraceHop represents a hop in a traceroute
type TraceHop struct {
	TraceID    int           `json:"trace_id"`
	ProbeTTL   int           `json:"probe_ttl"`
	IP         net.IP        `json:"ip"`
	ASN        *int64        `json:"asn,omitempty"`
	ASNMethod  *string       `json:"asn_method,omitempty"`
	ISO        *string       `json:"iso,omitempty"`
	ISOMethod  *string       `json:"iso_method,omitempty"`
	Org        *string       `json:"org,omitempty"`
	OrgMethod  *string       `json:"org_method,omitempty"`
	Threat     *int          `json:"threat,omitempty"`
	Annotation *IPAnnotation `json:"annotation,omitempty"`
}

// Traceroute represents a complete traceroute
type Traceroute struct {
	ID            int                    `json:"id"`
	Src           net.IP                 `json:"src"`
	Dst           net.IP                 `json:"dst"`
	SrcAnnotation *IPAnnotation          `json:"src_annotation,omitempty"`
	DstAnnotation *IPAnnotation          `json:"dst_annotation,omitempty"`
	TraceHops     []TraceHop             `json:"tracehops"`
	MonID         *string                `json:"mon_id,omitempty"`
	VPID          *int                   `json:"vp_id,omitempty"`
	SrcASN        *int64                 `json:"src_asn,omitempty"`
	SrcASNInfo    *ASN                   `json:"src_asn_info,omitempty"`
	SrcASNMethod  *string                `json:"src_asn_method,omitempty"`
	SrcISO        *string                `json:"src_iso,omitempty"`
	SrcISOMethod  *string                `json:"src_iso_method,omitempty"`
	SrcOrg        *string                `json:"src_org,omitempty"`
	SrcOrgMethod  *string                `json:"src_org_method,omitempty"`
	DstASN        *int64                 `json:"dst_asn,omitempty"`
	DstASNInfo    *ASN                   `json:"dst_asn_info,omitempty"`
	DstASNMethod  *string                `json:"dst_asn_method,omitempty"`
	DstISO        *string                `json:"dst_iso,omitempty"`
	DstISOMethod  *string                `json:"dst_iso_method,omitempty"`
	DstOrg        *string                `json:"dst_org,omitempty"`
	DstOrgMethod  *string                `json:"dst_org_method,omitempty"`
	Latitude      *float64               `json:"latitude,omitempty"`
	Longitude     *float64               `json:"longitude,omitempty"`
	Threat        *int                   `json:"threat,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
	VP            *VantagePoint          `json:"vp,omitempty"`
	TimeCreated   time.Time              `json:"time_created"`
	TimeModified  time.Time              `json:"time_modified"`
	Errors        []string               `json:"errors"`
	Finished      bool                   `json:"finished"`
}

// TraceSet represents a set of traceroutes
type TraceSet struct {
	ID           int       `json:"id"`
	Name         *string   `json:"name,omitempty"`
	Creator      *string   `json:"creator,omitempty"`
	TimeCreated  time.Time `json:"time_created"`
	TimeModified time.Time `json:"time_modified"`
	Tags         []string  `json:"tags"`
	Finished     bool      `json:"finished"`
	Errors       []string  `json:"errors"`
}

// TraceSetTraceroute represents the relationship between trace sets and traceroutes
type TraceSetTraceroute struct {
	SetID   int `json:"set_id"`
	TraceID int `json:"trace_id"`
}

// TraceSetTraceInfo represents additional info for traces in a set
type TraceSetTraceInfo struct {
	SetID       int    `json:"set_id"`
	TraceID     int    `json:"trace_id"`
	Description string `json:"description"`
}

// TraceSetCurated represents curated trace sets
type TraceSetCurated struct {
	SetID int `json:"set_id"`
}

// MonDstTraceroute represents the relationship between monitors and destination traceroutes
type MonDstTraceroute struct {
	Dst   string `json:"dst"`
	Trace int    `json:"trace"`
}

// TracerouteNode represents the relationship between traceroutes and nodes
type TracerouteNode struct {
	Hop   int `json:"hop"`
	Trace int `json:"trace"`
	Node  int `json:"node"`
}

// IPAnnotation represents IP address annotations
type IPAnnotation struct {
	IP           net.IP         `json:"ip"`
	TraceHops    []TraceHop     `json:"tracehops,omitempty"`
	VPs          []VantagePoint `json:"vps,omitempty"`
	Vendor       *Vendor        `json:"vendor,omitempty"`
	Name         *string        `json:"name,omitempty"`
	ASN          *int64         `json:"asn,omitempty"`
	ASNMethod    *string        `json:"asn_method,omitempty"`
	ASNInfo      *ASN           `json:"asn_info,omitempty"`
	ISO          *string        `json:"iso,omitempty"`
	ISOMethod    *string        `json:"iso_method,omitempty"`
	Country      *Country       `json:"country,omitempty"`
	Org          *string        `json:"org,omitempty"`
	OrgMethod    *string        `json:"org_method,omitempty"`
	Threat       *int           `json:"threat,omitempty"`
	VendorID     *int64         `json:"vendor_id,omitempty"`
	VendorName   *string        `json:"vendor_name,omitempty"`
	VendorSrc    *string        `json:"vendor_src,omitempty"`
	GeoCC        *string        `json:"geo_cc,omitempty"`
	GeoST        *string        `json:"geo_st,omitempty"`
	GeoPlace     *string        `json:"geo_place,omitempty"`
	GeoLatitude  *float64       `json:"geo_latitude,omitempty"`
	GeoLongitude *float64       `json:"geo_longitude,omitempty"`
	GeoMethod    *string        `json:"geo_method,omitempty"`
	ArkVP        *string        `json:"ark_vp,omitempty"`
	ArkRTT       *float64       `json:"ark_rtt,omitempty"`
	TimeCreated  time.Time      `json:"time_created"`
	TimeModified time.Time      `json:"time_modified"`
	Finished     bool           `json:"finished"`
}

// Suggestion represents search suggestions
type Suggestion struct {
	Key          string `json:"key"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	NumAddresses int    `json:"num_addresses"`
}

// Organization represents organization information (updated)
type Organization struct {
	Name   *string `json:"name,omitempty"`
	Method *string `json:"method,omitempty"`
}

// Reserved represents reserved IP information (updated)
type Reserved struct {
	Name    string `json:"name"`
	Network string `json:"nework"` // Note: keeping "nework" to match the JSON typo
}

// ArkPing represents ARK ping information (updated)
type ArkPing struct {
	VP  *string  `json:"vp,omitempty"`
	RTT *float64 `json:"rtt,omitempty"`
}

// Geo represents geographic information (updated)
type Geo struct {
	CC        *string  `json:"cc,omitempty"`
	ST        *string  `json:"st,omitempty"`
	Place     *string  `json:"place,omitempty"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
	Method    *string  `json:"method,omitempty"`
}

// PathfinderHop represents a hop in a pathfinder trace (from original code)
type PathfinderHop struct {
	IP           string       `json:"ip"`
	ProbeTTL     int          `json:"probe_ttl"`
	ASN          ASN          `json:"asn"`
	Country      Country      `json:"country,omitempty"`
	Organization Organization `json:"organization"`
	Reserved     Reserved     `json:"reserved,omitempty"`
	ArkPing      ArkPing      `json:"arkping,omitempty"`
	Geo          Geo          `json:"geo,omitempty"`
	Hostname     string       `json:"hostname,omitempty"`
	Threat       int          `json:"threat"`
}

// IPEndpoint represents an IP endpoint with all possible annotation fields
type IPEndpoint struct {
	IP           string        `json:"ip"`
	Reserved     *Reserved     `json:"reserved,omitempty"`
	ASN          *ASN          `json:"asn,omitempty"`
	Country      *Country      `json:"country,omitempty"`
	Organization *Organization `json:"organization,omitempty"`
	Vendor       *Vendor       `json:"vendor,omitempty"`
	ArkPing      *ArkPing      `json:"arkping,omitempty"`
	Geo          *Geo          `json:"geo,omitempty"`
	Threat       *int          `json:"threat,omitempty"`
}

// TracerouteHop represents a hop in the traceroute response
type TracerouteHop struct {
	IP           string        `json:"ip"`
	Hostname     *string       `json:"hostname,omitempty"`
	Reserved     *Reserved     `json:"reserved,omitempty"`
	ASN          *ASN          `json:"asn,omitempty"`
	Country      *Country      `json:"country,omitempty"`
	Organization *Organization `json:"organization,omitempty"`
	Vendor       *Vendor       `json:"vendor,omitempty"`
	ArkPing      *ArkPing      `json:"arkping,omitempty"`
	Geo          *Geo          `json:"geo,omitempty"`
	Threat       *int          `json:"threat,omitempty"`
	ProbeTTL     int           `json:"probe_ttl"`
}

// Data represents the main data structure (updated for complete response)
type Data struct {
	ID           int             `json:"id"`
	Src          IPEndpoint      `json:"src"`
	Dst          IPEndpoint      `json:"dst"`
	Monitor      *Monitor        `json:"monitor,omitempty"`
	Hops         []TracerouteHop `json:"hops"`
	Threat       *int            `json:"threat,omitempty"`
	Finished     bool            `json:"finished"`
	TimeCreated  time.Time       `json:"time_created"`
	TimeModified time.Time       `json:"time_modified"`
	Errors       []string        `json:"errors"`
}

// Response represents the API response structure (updated for complete JSON)
type Response struct {
	TotalCount int      `json:"totalCount"`
	PageSize   int      `json:"pageSize"`
	Page       int      `json:"page"`
	Data       []Data   `json:"data"`
	Errors     []string `json:"errors"`
}

// PFObj represents a pathfinder object (reverted to original)
type PFObj struct {
	Data   []int    `json:"data"`
	Errors []string `json:"errors"`
}
