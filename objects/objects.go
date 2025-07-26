package objects

import (
	"net"
	"time"
)

/* LLM Generated */
// scamper objects

type Tx struct {
	Sec   int    `json:"sec,omitempty"`
	Usec  int    `json:"usec,omitempty"`
	Ftime string `json:"ftime,omitempty"`
}

type MPLSLabel struct {
	MPLSTTL   int `json:"mpls_ttl,omitempty"`
	MPLSS     int `json:"mpls_s,omitempty"`
	MPLSEXP   int `json:"mpls_exp,omitempty"`
	MPLSLabel int `json:"mpls_label,omitempty"`
}

type ICMPExt struct {
	IECN       int         `json:"ie_cn,omitempty"`
	IECT       int         `json:"ie_ct,omitempty"`
	IEDL       int         `json:"ie_dl,omitempty"`
	MPLSLabels []MPLSLabel `json:"mpls_labels,omitempty"`
}

type ScamperHop struct {
	Addr      string    `json:"addr,omitempty"`
	ProbeTTL  int       `json:"probe_ttl,omitempty"`
	ProbeID   int       `json:"probe_id,omitempty"`
	ProbeSize int       `json:"probe_size,omitempty"`
	Tx        Tx        `json:"tx,omitempty"`
	RTT       float64   `json:"rtt,omitempty"`
	ReplyTTL  int       `json:"reply_ttl,omitempty"`
	ReplyTOS  int       `json:"reply_tos,omitempty"`
	ReplyIPID int       `json:"reply_ipid,omitempty"`
	ReplySize int       `json:"reply_size,omitempty"`
	ICMPType  int       `json:"icmp_type,omitempty"`
	ICMPCode  int       `json:"icmp_code,omitempty"`
	ICMPQTTL  int       `json:"icmp_q_ttl,omitempty"`
	ICMPQIPL  int       `json:"icmp_q_ipl,omitempty"`
	ICMPQTOS  int       `json:"icmp_q_tos,omitempty"`
	ICMPExts  []ICMPExt `json:"icmpext,omitempty"`
}

type Trace struct {
	Type       string       `json:"type,omitempty"`
	Version    string       `json:"version,omitempty"`
	UserID     int          `json:"userid,omitempty"`
	Method     string       `json:"method,omitempty"`
	Src        string       `json:"src,omitempty"`
	Dst        string       `json:"dst,omitempty"`
	Sport      int          `json:"sport,omitempty"`
	Dport      int          `json:"dport,omitempty"`
	StopReason string       `json:"stop_reason,omitempty"`
	StopData   int          `json:"stop_data,omitempty"`
	Start      Tx           `json:"start,omitempty"`
	HopCount   int          `json:"hop_count,omitempty"`
	Attempts   int          `json:"attempts,omitempty"`
	HopLimit   int          `json:"hoplimit,omitempty"`
	FirstHop   int          `json:"firsthop,omitempty"`
	Wait       int          `json:"wait,omitempty"`
	WaitProbe  int          `json:"wait_probe,omitempty"`
	TOS        int          `json:"tos,omitempty"`
	ProbeSize  int          `json:"probe_size,omitempty"`
	ProbeCount int          `json:"probe_count,omitempty"`
	Hops       []ScamperHop `json:"hops,omitempty"`
}

type Root struct {
	Data  Trace   `json:"data,omitempty"`
	MonID *string `json:"mon_id,omitempty"`
}

/* fin */

// pathfinder objects

// Country represents a country with threat level (updated)
type Country struct {
	ISO    string  `json:"iso,omitempty"`
	ISO3   *string `json:"iso3,omitempty"`
	Name   *string `json:"name,omitempty"`
	Threat *int    `json:"threat,omitempty"`
	Method *string `json:"method,omitempty"`
}

// Group represents a group with optional threat level
type Group struct {
	Name   string `json:"name,omitempty"`
	Threat *int   `json:"threat,omitempty"`
}

// CountryGroup represents the many-to-many relationship between countries and groups
type CountryGroup struct {
	Country string `json:"country,omitempty"`
	Group   string `json:"group,omitempty"`
}

// ASN represents an Autonomous System Number (updated for response)
type ASN struct {
	ASN     int64    `json:"asn,omitempty"`
	Name    *string  `json:"name,omitempty"`
	Country *Country `json:"country,omitempty"`
	Threat  *int     `json:"threat,omitempty"`
	Method  *string  `json:"method,omitempty"`
}

// Vendor represents a vendor/organization (updated for response)
type Vendor struct {
	ID      int64    `json:"id,omitempty"`
	Name    *string  `json:"name,omitempty"`
	Country *Country `json:"country,omitempty"`
	Threat  *int     `json:"threat,omitempty"`
	Method  *string  `json:"method,omitempty"`
}

// IPBlock represents an IP address block
type IPBlock struct {
	Start         net.IP  `json:"start,omitempty"`
	End           net.IP  `json:"end,omitempty"`
	ASN           *int64  `json:"asn,omitempty"`
	ASNMethod     *string `json:"asn_method,omitempty"`
	Country       *string `json:"country,omitempty"`
	CountryMethod *string `json:"country_method,omitempty"`
	Name          *string `json:"name,omitempty"`
	NameMethod    *string `json:"name_method,omitempty"`
}

// Monitor represents a monitoring point (simplified for response)
type Monitor struct {
	ID string `json:"id,omitempty"`
}

// VantagePoint represents a network vantage point
type VantagePoint struct {
	ID         int           `json:"id,omitempty"`
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
	ID       int     `json:"id,omitempty"`
	IP       net.IP  `json:"ip,omitempty"`
	Hostname *string `json:"hostname,omitempty"`
	ASN      *int    `json:"asn,omitempty"`
	OrgName  *string `json:"org_name,omitempty"`
	Country  *string `json:"country,omitempty"`
	VP       *int    `json:"vp,omitempty"`
}

// TraceHop represents a hop in a traceroute
type TraceHop struct {
	TraceID    int           `json:"trace_id,omitempty"`
	ProbeTTL   int           `json:"probe_ttl,omitempty"`
	IP         net.IP        `json:"ip,omitempty"`
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
	ID            int                    `json:"id,omitempty"`
	Src           net.IP                 `json:"src,omitempty"`
	Dst           net.IP                 `json:"dst,omitempty"`
	SrcAnnotation *IPAnnotation          `json:"src_annotation,omitempty"`
	DstAnnotation *IPAnnotation          `json:"dst_annotation,omitempty"`
	TraceHops     []TraceHop             `json:"tracehops,omitempty"`
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
	TimeCreated   time.Time              `json:"time_created,omitempty"`
	TimeModified  time.Time              `json:"time_modified,omitempty"`
	Errors        []string               `json:"errors,omitempty"`
	Finished      bool                   `json:"finished,omitempty"`
}

// TraceSet represents a set of traceroutes
type TraceSet struct {
	ID           int       `json:"id,omitempty"`
	Name         *string   `json:"name,omitempty"`
	Creator      *string   `json:"creator,omitempty"`
	TimeCreated  time.Time `json:"time_created,omitempty"`
	TimeModified time.Time `json:"time_modified,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	Finished     bool      `json:"finished,omitempty"`
	Errors       []string  `json:"errors,omitempty"`
}

// TraceSetTraceroute represents the relationship between trace sets and traceroutes
type TraceSetTraceroute struct {
	SetID   int `json:"set_id,omitempty"`
	TraceID int `json:"trace_id,omitempty"`
}

// TraceSetTraceInfo represents additional info for traces in a set
type TraceSetTraceInfo struct {
	SetID       int    `json:"set_id,omitempty"`
	TraceID     int    `json:"trace_id,omitempty"`
	Description string `json:"description,omitempty"`
}

// TraceSetCurated represents curated trace sets
type TraceSetCurated struct {
	SetID int `json:"set_id,omitempty"`
}

// MonDstTraceroute represents the relationship between monitors and destination traceroutes
type MonDstTraceroute struct {
	Dst   string `json:"dst,omitempty"`
	Trace int    `json:"trace,omitempty"`
}

// TracerouteNode represents the relationship between traceroutes and nodes
type TracerouteNode struct {
	Hop   int `json:"hop,omitempty"`
	Trace int `json:"trace,omitempty"`
	Node  int `json:"node,omitempty"`
}

// IPAnnotation represents IP address annotations
type IPAnnotation struct {
	IP           net.IP         `json:"ip,omitempty"`
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
	TimeCreated  time.Time      `json:"time_created,omitempty"`
	TimeModified time.Time      `json:"time_modified,omitempty"`
	Finished     bool           `json:"finished,omitempty"`
}

// Suggestion represents search suggestions
type Suggestion struct {
	Key          string `json:"key,omitempty"`
	ID           string `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	Type         string `json:"type,omitempty"`
	NumAddresses int    `json:"num_addresses,omitempty"`
}

// Organization represents organization information (updated)
type Organization struct {
	Name   *string `json:"name,omitempty"`
	Method *string `json:"method,omitempty"`
}

// Reserved represents reserved IP information (updated)
type Reserved struct {
	Name    string `json:"name,omitempty"`
	Network string `json:"network,omitempty"`
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
	IP           string       `json:"ip,omitempty"`
	ProbeTTL     int          `json:"probe_ttl,omitempty"`
	ASN          ASN          `json:"asn,omitempty"`
	Country      Country      `json:"country,omitempty"`
	Organization Organization `json:"organization,omitempty"`
	Reserved     Reserved     `json:"reserved,omitempty"`
	ArkPing      ArkPing      `json:"arkping,omitempty"`
	Geo          Geo          `json:"geo,omitempty"`
	Hostname     string       `json:"hostname,omitempty"`
	Threat       int          `json:"threat,omitempty"`
}

// IPEndpoint represents an IP endpoint with all possible annotation fields
type IPEndpoint struct {
	IP           string        `json:"ip,omitempty"`
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
	IP           string        `json:"ip,omitempty"`
	Hostname     *string       `json:"hostname,omitempty"`
	Reserved     *Reserved     `json:"reserved,omitempty"`
	ASN          *ASN          `json:"asn,omitempty"`
	Country      *Country      `json:"country,omitempty"`
	Organization *Organization `json:"organization,omitempty"`
	Vendor       *Vendor       `json:"vendor,omitempty"`
	ArkPing      *ArkPing      `json:"arkping,omitempty"`
	Geo          *Geo          `json:"geo,omitempty"`
	Threat       *int          `json:"threat,omitempty"`
	ProbeTTL     int           `json:"probe_ttl,omitempty"`
}

// Data represents the main data structure (updated for complete response)
type Data struct {
	ID           int             `json:"id,omitempty"`
	Src          IPEndpoint      `json:"src,omitempty"`
	Dst          IPEndpoint      `json:"dst,omitempty"`
	Monitor      *Monitor        `json:"monitor,omitempty"`
	Hops         []TracerouteHop `json:"hops,omitempty"`
	Threat       *int            `json:"threat,omitempty"`
	Finished     bool            `json:"finished,omitempty"`
	TimeCreated  time.Time       `json:"time_created,omitempty"`
	TimeModified time.Time       `json:"time_modified,omitempty"`
	Errors       []string        `json:"errors,omitempty"`
}

// Response represents the API response structure (updated for complete JSON)
type Response struct {
	TotalCount int      `json:"totalCount,omitempty"`
	PageSize   int      `json:"pageSize,omitempty"`
	Page       int      `json:"page,omitempty"`
	Data       []Data   `json:"data,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// PFObj represents a pathfinder object (reverted to original)
type PFObj struct {
	Data   []int    `json:"data,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

type TraceReq struct {
	Name    string   `json:"name,omitempty"`
	Creator string   `json:"creator,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}
