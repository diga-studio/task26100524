package bastiongrid

import "sort"

// fullWeek 表示未指定生效时段时的全周区间。
var fullWeek = []TimeRange{{Start: 0, End: MinutesPerWeek}}

// ruleTimeSet 返回规则的生效时段；空时段归一化为全周。
func ruleTimeSet(r Rule) []TimeRange {
	if len(r.Times) == 0 {
		return fullWeek
	}
	return r.Times
}

// ruleProtocols 返回规则协议覆盖的具体报文协议集合。
func ruleProtocols(p Protocol) []Protocol {
	if p == ProtocolANY {
		return []Protocol{ProtocolTCP, ProtocolUDP, ProtocolICMP}
	}
	return []Protocol{p}
}

// coverer 表示一条可能遮蔽目标规则的较早终止规则在某个协议上的投影。
type coverer struct {
	id        int
	times     []TimeRange
	portStart int
	portEnd   int
}

// Analyze 分析每条规则的生效性，返回按执行顺序排列的分析结果。
func Analyze(rules []Rule) []RuleAnalysis {
	ordered := sortedRules(rules)
	results := make([]RuleAnalysis, 0, len(ordered))
	for i, r := range ordered {
		results = append(results, analyzeRule(r, ordered[:i]))
	}
	return results
}

// analyzeRule 分析单条规则；earlier 为按执行顺序排列、先于该规则执行的全部规则。
func analyzeRule(r Rule, earlier []Rule) RuleAnalysis {
	res := RuleAnalysis{RuleID: r.ID, ShadowedBy: -1}
	times := ruleTimeSet(r)

	for _, p := range ruleProtocols(r.Protocol) {
		coverers := collectCoverers(r, earlier, p)
		segments := elementarySegments(times, coverers)
		for _, seg := range segments {
			if !inTimeSet(times, seg.Start) {
				continue
			}
			active := activeCoverers(coverers, seg.Start)
			if p == ProtocolICMP {
				if len(active) == 0 {
					res.ReachableWitness = firstPacket(res.ReachableWitness, Packet{
						SrcZone: r.SrcZone, DstZone: r.DstZone, Protocol: p, Minute: seg.Start,
					})
				} else {
					res.ShadowedWitness = firstPacket(res.ShadowedWitness, Packet{
						SrcZone: r.SrcZone, DstZone: r.DstZone, Protocol: p, Minute: seg.Start,
					})
				}
				continue
			}
			if port, ok := firstUncoveredPort(r.PortStart, r.PortEnd, active); ok {
				res.ReachableWitness = firstPacket(res.ReachableWitness, Packet{
					SrcZone: r.SrcZone, DstZone: r.DstZone, Protocol: p, Port: port, Minute: seg.Start,
				})
			}
			if port, ok := firstCoveredPort(r.PortStart, r.PortEnd, active); ok {
				res.ShadowedWitness = firstPacket(res.ShadowedWitness, Packet{
					SrcZone: r.SrcZone, DstZone: r.DstZone, Protocol: p, Port: port, Minute: seg.Start,
				})
			}
		}
	}

	if res.ShadowedWitness != nil {
		res.ShadowedBy = terminatorID(earlier, *res.ShadowedWitness)
	}
	switch {
	case res.ReachableWitness == nil && res.ShadowedWitness != nil:
		res.Status = StatusShadowed
	case res.ReachableWitness != nil && res.ShadowedWitness != nil:
		res.Status = StatusPartial
	default:
		res.Status = StatusEffective
	}
	return res
}

// firstPacket 返回已有的见证；若尚无为 nil 则采用新的候选。
func firstPacket(existing *Packet, candidate Packet) *Packet {
	if existing != nil {
		return existing
	}
	pkt := candidate
	return &pkt
}

// collectCoverers 收集同区域对、协议覆盖 p 的较早终止规则在协议 p 上的投影。
func collectCoverers(r Rule, earlier []Rule, p Protocol) []coverer {
	var out []coverer
	for _, e := range earlier {
		if e.Action == ActionLog {
			continue
		}
		if e.SrcZone != r.SrcZone || e.DstZone != r.DstZone {
			continue
		}
		if !matchesProtocol(e.Protocol, p) {
			continue
		}
		c := coverer{id: e.ID, times: ruleTimeSet(e), portStart: 0, portEnd: 65535}
		if e.Protocol == ProtocolTCP || e.Protocol == ProtocolUDP {
			c.portStart, c.portEnd = e.PortStart, e.PortEnd
		}
		out = append(out, c)
	}
	return out
}

// elementarySegments 由目标规则时段与各遮蔽者时段的端点切分出基本时间段。
func elementarySegments(times []TimeRange, coverers []coverer) []TimeRange {
	points := map[int]struct{}{}
	add := func(trs []TimeRange) {
		for _, tr := range trs {
			points[tr.Start] = struct{}{}
			points[tr.End] = struct{}{}
		}
	}
	add(times)
	for _, c := range coverers {
		add(c.times)
	}
	sorted := make([]int, 0, len(points))
	for pt := range points {
		sorted = append(sorted, pt)
	}
	sort.Ints(sorted)
	segments := make([]TimeRange, 0, len(sorted)-1)
	for i := 0; i+1 < len(sorted); i++ {
		if sorted[i] < sorted[i+1] {
			segments = append(segments, TimeRange{Start: sorted[i], End: sorted[i+1]})
		}
	}
	return segments
}

// inTimeSet 判断周分钟是否落在时段集合内。
func inTimeSet(times []TimeRange, minute int) bool {
	for _, tr := range times {
		if minute >= tr.Start && minute < tr.End {
			return true
		}
	}
	return false
}

// activeCoverers 返回在指定周分钟生效的遮蔽者。
func activeCoverers(coverers []coverer, minute int) []coverer {
	var out []coverer
	for _, c := range coverers {
		if inTimeSet(c.times, minute) {
			out = append(out, c)
		}
	}
	return out
}

// firstUncoveredPort 返回 [lo, hi] 中未被任何遮蔽者端口范围覆盖的第一个端口。
func firstUncoveredPort(lo, hi int, active []coverer) (int, bool) {
	cursor := lo
	ranges := make([][2]int, 0, len(active))
	for _, c := range active {
		ranges = append(ranges, [2]int{c.portStart, c.portEnd})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	for _, rg := range ranges {
		if rg[1] < cursor {
			continue
		}
		if rg[0] > cursor {
			return cursor, true
		}
		if rg[1]+1 > cursor {
			cursor = rg[1] + 1
		}
	}
	if cursor <= hi {
		return cursor, true
	}
	return 0, false
}

// firstCoveredPort 返回 [lo, hi] 中被某个遮蔽者端口范围覆盖的第一个端口。
func firstCoveredPort(lo, hi int, active []coverer) (int, bool) {
	best := hi + 1
	for _, c := range active {
		start := c.portStart
		if start < lo {
			start = lo
		}
		if start <= c.portEnd && start <= hi && start < best {
			best = start
		}
	}
	if best <= hi {
		return best, true
	}
	return 0, false
}

// terminatorID 在较早规则中找出实际终止该报文的规则编号；保证存在。
func terminatorID(earlier []Rule, pkt Packet) int {
	for _, e := range earlier {
		if e.Action == ActionLog {
			continue
		}
		if matches(e, pkt) {
			return e.ID
		}
	}
	return -1
}
