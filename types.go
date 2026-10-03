// Package bastiongrid 提供防火墙规则生效性分析能力。
// 策略与分析结果仅保存在内存，由上层直接调用。
package bastiongrid

// Protocol 表示报文或规则匹配的协议。
type Protocol string

const (
	ProtocolTCP  Protocol = "TCP"
	ProtocolUDP  Protocol = "UDP"
	ProtocolICMP Protocol = "ICMP"
	// ProtocolANY 仅用于规则，表示匹配 TCP/UDP/ICMP 且不限制端口。
	ProtocolANY Protocol = "ANY"
)

// Action 表示规则动作。
type Action string

const (
	ActionAllow Action = "ALLOW"
	ActionDeny  Action = "DENY"
	ActionLog   Action = "LOG"
)

// MinutesPerWeek 是一周的总分钟数；周分钟 0 表示周一 00:00（UTC）。
const MinutesPerWeek = 10080

// TimeRange 表示半开区间 [Start, End)，单位为 UTC 周分钟。
// 包含起点，不包含终点；End 最大可取 MinutesPerWeek。
type TimeRange struct {
	Start int
	End   int
}

// Rule 表示一条防火墙规则。
// 优先级数字越小越先执行；优先级相同按编号从小到大执行。
// PortStart/PortEnd 为包含两端的端口范围，仅当 Protocol 为 TCP 或 UDP 时有效；
// Protocol 为 ICMP 或 ANY 时忽略端口条件。
// Times 为非空、互不重叠的半开区间；为空表示全周生效。
type Rule struct {
	ID        int
	Priority  int
	SrcZone   string
	DstZone   string
	Protocol  Protocol
	PortStart int
	PortEnd   int
	Action    Action
	Times     []TimeRange
}

// Packet 表示一个待评估的报文。
// Protocol 只能为 TCP、UDP 或 ICMP；ICMP 报文的 Port 字段被忽略。
// Minute 为 UTC 周分钟，取值 [0, MinutesPerWeek)。
type Packet struct {
	SrcZone  string
	DstZone  string
	Protocol Protocol
	Port     int
	Minute   int
}

// Decision 表示对单个报文的评估结果。
type Decision struct {
	// Verdict 为最终动作：ALLOW 或 DENY（无终止规则时默认 DENY）。
	Verdict Action
	// RuleID 为实际终止评估的规则编号；默认 DENY 时为 -1。
	RuleID int
	// Logged 为评估过程中命中 LOG 规则的编号，按执行顺序排列。
	Logged []int
}

// Status 表示一条规则的生效性判定。
type Status string

const (
	// StatusEffective 表示规则匹配的全部报文都能执行到它。
	StatusEffective Status = "EFFECTIVE"
	// StatusShadowed 表示规则匹配的全部报文都被较早的终止规则拦下。
	StatusShadowed Status = "SHADOWED"
	// StatusPartial 表示规则部分报文可达、部分被遮蔽。
	StatusPartial Status = "PARTIAL"
)

// RuleAnalysis 表示对单条规则的生效性分析结果。
type RuleAnalysis struct {
	RuleID int
	Status Status
	// ReachableWitness 为可达部分的具体报文；可达部分为空时为 nil。
	ReachableWitness *Packet
	// ShadowedWitness 为被遮蔽部分的具体报文；被遮蔽部分为空时为 nil。
	ShadowedWitness *Packet
	// ShadowedBy 为实际终止 ShadowedWitness 的较早规则编号；无被遮蔽见证时为 -1。
	ShadowedBy int
}
