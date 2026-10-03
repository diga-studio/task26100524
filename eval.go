package bastiongrid

import "sort"

// sortedRules 返回按执行顺序（优先级升序，编号升序）排序的规则副本。
func sortedRules(rules []Rule) []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// matchesProtocol 判断规则协议是否匹配报文协议。
func matchesProtocol(ruleProto, pktProto Protocol) bool {
	return ruleProto == ProtocolANY || ruleProto == pktProto
}

// matchesTime 判断周分钟是否落在规则的任一生效时段内；空时段表示全周。
func matchesTime(times []TimeRange, minute int) bool {
	if len(times) == 0 {
		return true
	}
	for _, tr := range times {
		if minute >= tr.Start && minute < tr.End {
			return true
		}
	}
	return false
}

// matches 判断规则是否匹配报文。
func matches(r Rule, pkt Packet) bool {
	if r.SrcZone != pkt.SrcZone || r.DstZone != pkt.DstZone {
		return false
	}
	if !matchesProtocol(r.Protocol, pkt.Protocol) {
		return false
	}
	// 仅当规则协议为具体的 TCP/UDP 时才检查端口；ANY 与 ICMP 不限制端口。
	if r.Protocol == ProtocolTCP || r.Protocol == ProtocolUDP {
		if pkt.Port < r.PortStart || pkt.Port > r.PortEnd {
			return false
		}
	}
	return matchesTime(r.Times, pkt.Minute)
}

// Evaluate 按规则顺序评估单个报文，返回最终决策。
// 命中 ALLOW 或 DENY 立即终止；命中 LOG 记录编号并继续；无终止规则时默认 DENY。
func Evaluate(rules []Rule, pkt Packet) Decision {
	logged := []int{}
	for _, r := range sortedRules(rules) {
		if !matches(r, pkt) {
			continue
		}
		switch r.Action {
		case ActionLog:
			logged = append(logged, r.ID)
		default:
			return Decision{Verdict: r.Action, RuleID: r.ID, Logged: logged}
		}
	}
	return Decision{Verdict: ActionDeny, RuleID: -1, Logged: logged}
}
