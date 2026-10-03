package bastiongrid

// Matches 判断规则是否匹配报文。
func (r Rule) Matches(p Packet) bool {
	if r.SrcZone != p.SrcZone || r.DstZone != p.DstZone {
		return false
	}
	return r.matchesAt(p.Protocol, p.Port, p.WeekMinute)
}

// matchesAt 判断规则在指定协议、端口、周分钟上是否匹配（区域对相同的前提下）。
func (r Rule) matchesAt(proto Protocol, port, weekMinute int) bool {
	switch r.Protocol {
	case ProtocolANY:
		// 匹配三种协议且不限制端口。
	case ProtocolTCP, ProtocolUDP:
		if r.Protocol != proto {
			return false
		}
		if port < r.PortStart || port > r.PortEnd {
			return false
		}
	case ProtocolICMP:
		if proto != ProtocolICMP {
			return false
		}
	default:
		return false
	}
	return r.coversMinute(weekMinute)
}

// coversMinute 判断规则的生效时段是否覆盖指定周分钟。
func (r Rule) coversMinute(weekMinute int) bool {
	if len(r.Intervals) == 0 {
		return true
	}
	for _, iv := range r.Intervals {
		if weekMinute >= iv.Start && weekMinute < iv.End {
			return true
		}
	}
	return false
}

// protocols 返回规则匹配的协议集合（ANY 展开为三种协议）。
func (r Rule) protocols() []Protocol {
	if r.Protocol == ProtocolANY {
		return []Protocol{ProtocolTCP, ProtocolUDP, ProtocolICMP}
	}
	return []Protocol{r.Protocol}
}

// portRangeFor 返回规则在指定协议下覆盖的端口范围 [lo, hi]（闭区间）。
// ICMP 不限制端口，归一化为全范围，便于统一做空间运算。
func (r Rule) portRangeFor(proto Protocol) (lo, hi int) {
	if proto == ProtocolICMP || r.Protocol == ProtocolANY {
		return 0, 65535
	}
	return r.PortStart, r.PortEnd
}

// intervals 返回规则的生效时段；未指定时归一化为全周。
func (r Rule) intervals() []TimeInterval {
	if len(r.Intervals) == 0 {
		return []TimeInterval{{Start: 0, End: WeekMinutes}}
	}
	return r.Intervals
}
