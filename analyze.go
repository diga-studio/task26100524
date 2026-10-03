package bastiongrid

import "sort"

// rect 端口闭区间 [portLo, portHi] 与时间半开区间 [tStart, tEnd) 的二维矩形。
type rect struct {
	portLo, portHi int
	tStart, tEnd   int
}

// intersect 返回两个矩形的交集；第二个返回值表示是否非空。
func intersect(a, b rect) (rect, bool) {
	r := rect{
		portLo: max(a.portLo, b.portLo),
		portHi: min(a.portHi, b.portHi),
		tStart: max(a.tStart, b.tStart),
		tEnd:   min(a.tEnd, b.tEnd),
	}
	return r, r.portLo <= r.portHi && r.tStart < r.tEnd
}

// subtract 返回 r 去掉 b 后剩余的矩形（最多 4 个）。
func subtract(r, b rect) []rect {
	inter, ok := intersect(r, b)
	if !ok {
		return []rect{r}
	}
	var out []rect
	// 时间方向下侧
	if r.tStart < inter.tStart {
		out = append(out, rect{r.portLo, r.portHi, r.tStart, inter.tStart})
	}
	// 时间方向上侧
	if inter.tEnd < r.tEnd {
		out = append(out, rect{r.portLo, r.portHi, inter.tEnd, r.tEnd})
	}
	// 中间条带的端口左、右两侧
	if r.portLo < inter.portLo {
		out = append(out, rect{r.portLo, inter.portLo - 1, inter.tStart, inter.tEnd})
	}
	if inter.portHi < r.portHi {
		out = append(out, rect{inter.portHi + 1, r.portHi, inter.tStart, inter.tEnd})
	}
	return out
}

// subtractAll 从 region 中依次减去所有 cover 矩形，返回剩余部分。
func subtractAll(region []rect, cover []rect) []rect {
	for _, c := range cover {
		var next []rect
		for _, r := range region {
			next = append(next, subtract(r, c)...)
		}
		region = next
		if len(region) == 0 {
			break
		}
	}
	return region
}

// ruleRects 返回规则在指定协议下覆盖的矩形集合（调用方需保证协议属于该规则）。
func ruleRects(r Rule, proto Protocol) []rect {
	lo, hi := r.portRangeFor(proto)
	var out []rect
	for _, iv := range r.intervals() {
		out = append(out, rect{lo, hi, iv.Start, iv.End})
	}
	return out
}

// executionOrder 返回按 (Priority, ID) 排序后的规则副本。
func executionOrder(rules []Rule) []Rule {
	ordered := make([]Rule, len(rules))
	copy(ordered, rules)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].ID < ordered[j].ID
	})
	return ordered
}

// terminates 判断规则动作是否会终止匹配流程。
func terminates(a Action) bool {
	return a == ActionAllow || a == ActionDeny
}

// Analyze 分析一组规则的生效性。规则之间通过优先级与编号确定执行顺序。
// 输入规则需满足各自约束（唯一编号、合法时段等），调用方负责保证。
func Analyze(rules []Rule) AnalysisResult {
	ordered := executionOrder(rules)
	result := AnalysisResult{Rules: make([]RuleAnalysis, 0, len(ordered))}

	for i, target := range ordered {
		earlier := ordered[:i]
		analysis := RuleAnalysis{RuleID: target.ID, ShadowedBy: -1}

		var uncovered []rect
		var uncoveredProto Protocol
		shadowed := false
		var shadowedProto Protocol
		var shadowedRect rect
		shadowedBy := -1

		for _, proto := range target.protocols() {
			region := ruleRects(target, proto)
			var cover []rect
			for _, other := range earlier {
				if !terminates(other.Action) {
					continue
				}
				if other.SrcZone != target.SrcZone || other.DstZone != target.DstZone {
					continue
				}
				if !containsProtocol(other.protocols(), proto) {
					continue
				}
				otherRects := ruleRects(other, proto)
				cover = append(cover, otherRects...)
				// 记录第一个（执行序最早）与本规则相交的终止规则。
				if shadowedBy == -1 {
					for _, or := range otherRects {
						for _, rr := range region {
							if inter, ok := intersect(rr, or); ok {
								shadowed = true
								shadowedProto = proto
								shadowedRect = inter
								shadowedBy = other.ID
								break
							}
						}
						if shadowedBy != -1 {
							break
						}
					}
				}
			}
			rest := subtractAll(region, cover)
			if len(rest) > 0 && uncovered == nil {
				uncovered = rest
				uncoveredProto = proto
			}
		}

		switch {
		case !shadowed:
			analysis.Verdict = VerdictFullyEffective
		case len(uncovered) == 0:
			analysis.Verdict = VerdictFullyShadowed
		default:
			analysis.Verdict = VerdictPartiallyShadowed
		}

		if len(uncovered) > 0 {
			pkt := packetFromRect(target, uncoveredProto, uncovered[0])
			analysis.ReachableWitness = &pkt
		}
		if shadowed {
			pkt := packetFromRect(target, shadowedProto, shadowedRect)
			analysis.ShadowedWitness = &pkt
			analysis.ShadowedBy = shadowedBy
		}

		result.Rules = append(result.Rules, analysis)
	}
	return result
}

// packetFromRect 在矩形内取一个具体报文（端口下界、时间下界）。
func packetFromRect(target Rule, proto Protocol, r rect) Packet {
	port := 0
	if proto != ProtocolICMP {
		port = r.portLo
	}
	return Packet{
		SrcZone:    target.SrcZone,
		DstZone:    target.DstZone,
		Protocol:   proto,
		Port:       port,
		WeekMinute: r.tStart,
	}
}

func containsProtocol(list []Protocol, p Protocol) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}
