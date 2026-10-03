// Package bastiongrid 提供 BastionGrid 防火墙规则的生效性分析。
// 全部数据仅保存在内存中，由上层直接调用。
package bastiongrid

// Protocol 报文协议。
type Protocol string

const (
	ProtocolTCP  Protocol = "TCP"
	ProtocolUDP  Protocol = "UDP"
	ProtocolICMP Protocol = "ICMP"
	// ProtocolANY 仅用于规则：匹配全部三种协议且不限制端口。
	ProtocolANY Protocol = "ANY"
)

// Action 规则动作。
type Action string

const (
	ActionAllow Action = "ALLOW"
	ActionDeny  Action = "DENY"
	ActionLog   Action = "LOG"
)

// 周分钟取值范围：[0, WeekMinutes)，10080 表示下周一 00:00，不属于本周。
const WeekMinutes = 10080

// TimeInterval UTC 周分钟半开区间 [Start, End)，包含起点不包含终点。
type TimeInterval struct {
	Start int
	End   int
}

// Rule 一条防火墙规则。
type Rule struct {
	ID        int    // 唯一编号
	Priority  int    // 数字越小越先执行；相同则按编号从小到大
	SrcZone   string // 源区域标识，精确匹配
	DstZone   string // 目的区域标识，精确匹配
	Protocol  Protocol
	PortStart int // TCP/UDP 端口范围，包含两端；ICMP/ANY 忽略
	PortEnd   int
	Action    Action
	Intervals []TimeInterval // 非空、互不重叠的半开区间；空表示全周
}

// Packet 一个具体报文，用作见证。
type Packet struct {
	SrcZone    string
	DstZone    string
	Protocol   Protocol // 仅 TCP/UDP/ICMP
	Port       int      // ICMP 时为 0
	WeekMinute int      // [0, WeekMinutes)
}

// Verdict 单条规则的生效性判定。
type Verdict int

const (
	VerdictFullyEffective    Verdict = iota // 完全有效
	VerdictFullyShadowed                    // 完全遮蔽
	VerdictPartiallyShadowed                // 部分遮蔽
)

func (v Verdict) String() string {
	switch v {
	case VerdictFullyEffective:
		return "FULLY_EFFECTIVE"
	case VerdictFullyShadowed:
		return "FULLY_SHADOWED"
	case VerdictPartiallyShadowed:
		return "PARTIALLY_SHADOWED"
	}
	return "UNKNOWN"
}

// RuleAnalysis 单条规则的分析结果。
type RuleAnalysis struct {
	RuleID  int
	Verdict Verdict
	// ReachableWitness 可达部分非空时给出一个能执行到本规则的报文。
	ReachableWitness *Packet
	// ShadowedWitness 被遮蔽部分非空时给出一个被较早终止规则拦下的报文。
	ShadowedWitness *Packet
	// ShadowedBy 实际终止 ShadowedWitness 的较早规则编号。
	ShadowedBy int
}

// AnalysisResult 全部分析结果，按执行顺序排列。
type AnalysisResult struct {
	Rules []RuleAnalysis
}
