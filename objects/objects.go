package objects

import "time"

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

/* Generated by LLM */

type Country struct {
	Name   string `json:"name"`
	ISO    string `json:"iso"`
	Threat int    `json:"threat"`
}

type ASN struct {
	ASN     int     `json:"asn"`
	Name    string  `json:"name"`
	Country Country `json:"country"`
	Threat  int     `json:"threat"`
}

type Organization struct {
	Name   string `json:"name"`
	Method string `json:"method"`
}

type Reserved struct {
	Name    string `json:"name"`
	Network string `json:"nework"`
}

type ArkPing struct {
	VP  string  `json:"vp"`
	RTT float64 `json:"rtt"`
}

type Geo struct {
	Method string `json:"method"`
}

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

type Data struct {
	ID           int             `json:"id"`
	Src          string          `json:"src"`
	Dst          string          `json:"dst"`
	Hops         []PathfinderHop `json:"hops"`
	Finished     bool            `json:"finished"`
	TimeCreated  time.Time       `json:"time_created"`
	TimeModified time.Time       `json:"time_modified"`
	Errors       []string        `json:"errors"`
}

type Response struct {
	TotalCount int      `json:"totalCount"`
	PageSize   int      `json:"pageSize"`
	Page       int      `json:"page"`
	Data       []Data   `json:"data"`
	Errors     []string `json:"errors"`
}

/* Fin */

type PFObj struct {
	Data   []int
	Errors []string
}
