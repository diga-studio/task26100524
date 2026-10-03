package bastiongrid

import "testing"

func findAnalysis(t *testing.T, res AnalysisResult, id int) RuleAnalysis {
	t.Helper()
	for _, ra := range res.Rules {
		if ra.RuleID == id {
			return ra
		}
	}
	t.Fatalf("rule %d not found in result", id)
	return RuleAnalysis{}
}

// 多条较早规则合起来完全覆盖后续规则，但任意一条单独都不能覆盖。
func TestFullyShadowedByCombinedRules(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 100, PortEnd: 149, Action: ActionDeny},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 150, PortEnd: 200, Action: ActionDeny},
		{ID: 3, Priority: 3, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 100, PortEnd: 200, Action: ActionAllow},
	}
	res := Analyze(rules)

	ra := findAnalysis(t, res, 3)
	if ra.Verdict != VerdictFullyShadowed {
		t.Fatalf("rule 3 verdict = %v, want FULLY_SHADOWED", ra.Verdict)
	}
	if ra.ReachableWitness != nil {
		t.Fatalf("rule 3 should have no reachable witness, got %+v", *ra.ReachableWitness)
	}
	if ra.ShadowedWitness == nil {
		t.Fatal("rule 3 should have a shadowed witness")
	}
	// 见证必须可复现：模拟该报文，确实被 ShadowedBy 指出的规则终止。
	w := *ra.ShadowedWitness
	dec := Decide(rules, w)
	if dec.RuleID != ra.ShadowedBy {
		t.Fatalf("witness terminated by rule %d, but ShadowedBy = %d", dec.RuleID, ra.ShadowedBy)
	}
	if dec.RuleID != 1 && dec.RuleID != 2 {
		t.Fatalf("witness should be terminated by rule 1 or 2, got %d", dec.RuleID)
	}
	if !rules[2].Matches(w) {
		t.Fatalf("shadowed witness %+v does not match rule 3", w)
	}

	// 单独只有规则 1 时，规则 3 不应被完全遮蔽。
	res2 := Analyze([]Rule{rules[0], rules[2]})
	if got := findAnalysis(t, res2, 3).Verdict; got != VerdictPartiallyShadowed {
		t.Fatalf("with only rule 1, rule 3 verdict = %v, want PARTIALLY_SHADOWED", got)
	}
}

// 只留下 1 分钟与 1 个端口的交叉缺口，结果必须为部分遮蔽，可达见证落在缺口内。
func TestPartiallyShadowedTinyGap(t *testing.T) {
	// 目标规则：TCP 端口 100-200，周分钟 [0,100)。
	// 三条较早 DENY 规则覆盖除 (端口150, 分钟99) 外的全部空间。
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 100, PortEnd: 200, Action: ActionDeny,
			Intervals: []TimeInterval{{Start: 0, End: 99}}},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 100, PortEnd: 149, Action: ActionDeny,
			Intervals: []TimeInterval{{Start: 99, End: 100}}},
		{ID: 3, Priority: 3, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 151, PortEnd: 200, Action: ActionDeny,
			Intervals: []TimeInterval{{Start: 99, End: 100}}},
		{ID: 4, Priority: 4, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 100, PortEnd: 200, Action: ActionAllow,
			Intervals: []TimeInterval{{Start: 0, End: 100}}},
	}
	res := Analyze(rules)

	ra := findAnalysis(t, res, 4)
	if ra.Verdict != VerdictPartiallyShadowed {
		t.Fatalf("rule 4 verdict = %v, want PARTIALLY_SHADOWED", ra.Verdict)
	}
	if ra.ReachableWitness == nil {
		t.Fatal("rule 4 should have a reachable witness")
	}
	w := *ra.ReachableWitness
	if w.Port != 150 || w.WeekMinute != 99 {
		t.Fatalf("reachable witness = port %d minute %d, want port 150 minute 99", w.Port, w.WeekMinute)
	}
	// 可复现：该报文应执行到规则 4 并被 ALLOW。
	dec := Decide(rules, w)
	if dec.RuleID != 4 || dec.Action != ActionAllow {
		t.Fatalf("reachable witness decision = %+v, want ALLOW by rule 4", dec)
	}

	// 被遮蔽见证应被规则 1 终止（执行序最早的相交终止规则）。
	if ra.ShadowedWitness == nil {
		t.Fatal("rule 4 should have a shadowed witness")
	}
	sw := *ra.ShadowedWitness
	dec2 := Decide(rules, sw)
	if dec2.RuleID != ra.ShadowedBy {
		t.Fatalf("shadowed witness terminated by %d, ShadowedBy = %d", dec2.RuleID, ra.ShadowedBy)
	}
	if ra.ShadowedBy != 1 {
		t.Fatalf("ShadowedBy = %d, want 1", ra.ShadowedBy)
	}
}

// 没有被任何较早规则遮蔽时判为完全有效。
func TestFullyEffective(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionAllow},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443, Action: ActionAllow},
	}
	res := Analyze(rules)
	for _, id := range []int{1, 2} {
		ra := findAnalysis(t, res, id)
		if ra.Verdict != VerdictFullyEffective {
			t.Fatalf("rule %d verdict = %v, want FULLY_EFFECTIVE", id, ra.Verdict)
		}
		if ra.ReachableWitness == nil {
			t.Fatalf("rule %d should have a reachable witness", id)
		}
		if ra.ShadowedWitness != nil {
			t.Fatalf("rule %d should have no shadowed witness", id)
		}
	}
}

// LOG 不遮蔽后续规则；相同动作也会造成遮蔽。
func TestLogDoesNotShadowAndSameActionShadows(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionLog},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionAllow},
	}
	res := Analyze(rules)
	if got := findAnalysis(t, res, 2).Verdict; got != VerdictFullyEffective {
		t.Fatalf("LOG must not shadow: verdict = %v, want FULLY_EFFECTIVE", got)
	}

	rules[0].Action = ActionAllow // 相同动作（ALLOW）也遮蔽
	res = Analyze(rules)
	ra := findAnalysis(t, res, 2)
	if ra.Verdict != VerdictFullyShadowed {
		t.Fatalf("same-action ALLOW should shadow: verdict = %v, want FULLY_SHADOWED", ra.Verdict)
	}
	if ra.ShadowedBy != 1 {
		t.Fatalf("ShadowedBy = %d, want 1", ra.ShadowedBy)
	}
}

// 优先级相同按编号排序；不同区域对互不影响。
func TestOrderingAndZoneIsolation(t *testing.T) {
	rules := []Rule{
		{ID: 5, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionAllow},
		{ID: 3, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionDeny},
		{ID: 7, Priority: 1, SrcZone: "x", DstZone: "y", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionDeny},
	}
	res := Analyze(rules)
	// 同优先级时编号 3 先执行，遮蔽编号 5。
	if got := findAnalysis(t, res, 5).Verdict; got != VerdictFullyShadowed {
		t.Fatalf("rule 5 verdict = %v, want FULLY_SHADOWED", got)
	}
	// 区域对不同，不受影响。
	if got := findAnalysis(t, res, 7).Verdict; got != VerdictFullyEffective {
		t.Fatalf("rule 7 verdict = %v, want FULLY_EFFECTIVE", got)
	}
}

// ANY 协议规则与具体协议规则之间的遮蔽；ICMP 无端口。
func TestAnyProtocolAndICMP(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionDeny},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolICMP, Action: ActionAllow},
	}
	res := Analyze(rules)
	ra := findAnalysis(t, res, 2)
	if ra.Verdict != VerdictFullyShadowed {
		t.Fatalf("ANY should shadow ICMP rule: verdict = %v", ra.Verdict)
	}
	if ra.ShadowedWitness.Protocol != ProtocolICMP || ra.ShadowedWitness.Port != 0 {
		t.Fatalf("ICMP witness = %+v, want protocol ICMP port 0", *ra.ShadowedWitness)
	}

	// 反过来：先执行的 ICMP 规则只遮蔽 ANY 规则的 ICMP 部分 → 部分遮蔽。
	icmpFirst := Rule{ID: 3, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolICMP, Action: ActionAllow}
	anySecond := Rule{ID: 4, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionDeny}
	res2 := Analyze([]Rule{icmpFirst, anySecond})
	ra2 := findAnalysis(t, res2, 4)
	if ra2.Verdict != VerdictPartiallyShadowed {
		t.Fatalf("ICMP should only partially shadow ANY: verdict = %v", ra2.Verdict)
	}
	if ra2.ReachableWitness.Protocol == ProtocolICMP {
		t.Fatalf("reachable witness should not be ICMP: %+v", *ra2.ReachableWitness)
	}
}

// 半开区间边界：终点分钟不被覆盖。
func TestHalfOpenInterval(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionDeny,
			Intervals: []TimeInterval{{Start: 10, End: 20}}},
	}
	if rules[0].Matches(Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, Port: 80, WeekMinute: 20}) {
		t.Fatal("minute 20 should not be covered by [10,20)")
	}
	if !rules[0].Matches(Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, Port: 80, WeekMinute: 10}) {
		t.Fatal("minute 10 should be covered by [10,20)")
	}
}

// 无终止规则时默认 DENY；LOG 命中被记录。
func TestDecideDefaultDenyAndLog(t *testing.T) {
	rules := []Rule{
		{ID: 9, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionLog},
	}
	dec := Decide(rules, Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, Port: 80, WeekMinute: 0})
	if dec.Action != ActionDeny || dec.RuleID != -1 {
		t.Fatalf("decision = %+v, want default DENY", dec)
	}
	if len(dec.Logged) != 1 || dec.Logged[0] != 9 {
		t.Fatalf("logged = %v, want [9]", dec.Logged)
	}
}
