package bastiongrid

import "testing"

// findAnalysis 按规则编号查找分析结果。
func findAnalysis(t *testing.T, results []RuleAnalysis, id int) RuleAnalysis {
	t.Helper()
	for _, r := range results {
		if r.RuleID == id {
			return r
		}
	}
	t.Fatalf("no analysis for rule %d", id)
	return RuleAnalysis{}
}

// assertReachable 验证可达见证确实能执行到目标规则本身。
func assertReachable(t *testing.T, rules []Rule, target Rule, witness *Packet) {
	t.Helper()
	if witness == nil {
		t.Fatal("expected reachable witness, got nil")
	}
	if !matches(target, *witness) {
		t.Fatalf("reachable witness %+v does not match target rule %d", *witness, target.ID)
	}
	d := Evaluate(rules, *witness)
	if target.Action == ActionLog {
		for _, id := range d.Logged {
			if id == target.ID {
				return
			}
		}
		t.Fatalf("reachable witness did not execute LOG rule %d: %+v", target.ID, d)
		return
	}
	if d.RuleID != target.ID {
		t.Fatalf("reachable witness terminated by rule %d, want %d", d.RuleID, target.ID)
	}
}

// assertShadowed 验证被遮蔽见证匹配目标规则、且被 ShadowedBy 指定的较早规则实际终止。
func assertShadowed(t *testing.T, rules []Rule, target Rule, a RuleAnalysis) {
	t.Helper()
	if a.ShadowedWitness == nil {
		t.Fatal("expected shadowed witness, got nil")
	}
	if !matches(target, *a.ShadowedWitness) {
		t.Fatalf("shadowed witness %+v does not match target rule %d", *a.ShadowedWitness, target.ID)
	}
	if a.ShadowedBy == -1 || a.ShadowedBy == target.ID {
		t.Fatalf("invalid ShadowedBy %d", a.ShadowedBy)
	}
	d := Evaluate(rules, *a.ShadowedWitness)
	if d.RuleID != a.ShadowedBy {
		t.Fatalf("shadowed witness terminated by %d, want %d", d.RuleID, a.ShadowedBy)
	}
	if d.Verdict == ActionLog {
		t.Fatalf("shadowed witness must be terminated, got %+v", d)
	}
}

// 多条较早规则合起来完全覆盖后续规则，但任意一条单独都不能覆盖。
func TestAnalyzeJointlyCoveringRules(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 10, SrcZone: "dmz", DstZone: "core", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 60, Action: ActionDeny, Times: []TimeRange{{Start: 0, End: 100}}},
		{ID: 2, Priority: 20, SrcZone: "dmz", DstZone: "core", Protocol: ProtocolTCP, PortStart: 40, PortEnd: 100, Action: ActionDeny, Times: []TimeRange{{Start: 0, End: 100}}},
		{ID: 10, Priority: 100, SrcZone: "dmz", DstZone: "core", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 100, Action: ActionAllow, Times: []TimeRange{{Start: 0, End: 100}}},
	}
	results := Analyze(rules)
	a := findAnalysis(t, results, 10)
	if a.Status != StatusShadowed {
		t.Fatalf("status = %s, want SHADOWED", a.Status)
	}
	if a.ReachableWitness != nil {
		t.Fatalf("reachable witness should be nil, got %+v", *a.ReachableWitness)
	}
	assertShadowed(t, rules, rules[2], a)

	// 任意一条单独都不能覆盖：去掉规则 2 后，规则 10 变为部分遮蔽。
	partial := Analyze([]Rule{rules[0], rules[2]})
	a = findAnalysis(t, partial, 10)
	if a.Status != StatusPartial {
		t.Fatalf("single coverer: status = %s, want PARTIAL", a.Status)
	}
}

// 只留下 1 分钟与 1 个端口的交叉缺口，结果必须为部分遮蔽，可达见证落在缺口内。
func TestAnalyzeSingleMinuteSinglePortGap(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 10, SrcZone: "dmz", DstZone: "core", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 99, Action: ActionDeny},
		{ID: 2, Priority: 20, SrcZone: "dmz", DstZone: "core", Protocol: ProtocolTCP, PortStart: 101, PortEnd: 65535, Action: ActionDeny},
		{ID: 3, Priority: 30, SrcZone: "dmz", DstZone: "core", Protocol: ProtocolTCP, PortStart: 100, PortEnd: 100, Action: ActionDeny, Times: []TimeRange{{Start: 0, End: 60}, {Start: 61, End: MinutesPerWeek}}},
		{ID: 10, Priority: 100, SrcZone: "dmz", DstZone: "core", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 65535, Action: ActionAllow},
	}
	results := Analyze(rules)
	a := findAnalysis(t, results, 10)
	if a.Status != StatusPartial {
		t.Fatalf("status = %s, want PARTIAL", a.Status)
	}
	w := a.ReachableWitness
	if w == nil {
		t.Fatal("reachable witness is nil")
	}
	// 唯一缺口：端口 100、周分钟 60。
	if w.Port != 100 || w.Minute != 60 {
		t.Fatalf("reachable witness = %+v, want port 100 minute 60", *w)
	}
	assertReachable(t, rules, rules[3], w)
	assertShadowed(t, rules, rules[3], a)
}

// 无遮蔽的规则完全有效。
func TestAnalyzeFullyEffective(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionAllow},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolUDP, PortStart: 80, PortEnd: 80, Action: ActionDeny},
	}
	results := Analyze(rules)
	a := findAnalysis(t, results, 2)
	if a.Status != StatusEffective {
		t.Fatalf("status = %s, want EFFECTIVE", a.Status)
	}
	if a.ShadowedWitness != nil || a.ShadowedBy != -1 {
		t.Fatalf("unexpected shadowed witness: %+v", a)
	}
	assertReachable(t, rules, rules[1], a.ReachableWitness)
}

// LOG 不遮蔽后续规则。
func TestAnalyzeLogDoesNotShadow(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionLog},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 65535, Action: ActionAllow},
	}
	results := Analyze(rules)
	a := findAnalysis(t, results, 2)
	if a.Status != StatusEffective {
		t.Fatalf("status = %s, want EFFECTIVE", a.Status)
	}
}

// 相同动作也会造成遮蔽。
func TestAnalyzeSameActionShadows(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 65535, Action: ActionAllow},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 65535, Action: ActionAllow},
	}
	results := Analyze(rules)
	a := findAnalysis(t, results, 2)
	if a.Status != StatusShadowed {
		t.Fatalf("status = %s, want SHADOWED", a.Status)
	}
	if a.ShadowedBy != 1 {
		t.Fatalf("ShadowedBy = %d, want 1", a.ShadowedBy)
	}
}

// 被遮蔽见证必须指向实际终止它的较早规则，而不是任意重叠规则。
func TestAnalyzeShadowedByActualTerminator(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 50, Action: ActionDeny},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 100, Action: ActionDeny},
		{ID: 3, Priority: 3, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 100, Action: ActionAllow},
	}
	results := Analyze(rules)
	a := findAnalysis(t, results, 3)
	if a.Status != StatusShadowed {
		t.Fatalf("status = %s, want SHADOWED", a.Status)
	}
	// 见证端口 0 同时被规则 1、2 覆盖，实际终止它的是更早的规则 1。
	if a.ShadowedWitness == nil || a.ShadowedBy != 1 {
		t.Fatalf("ShadowedBy = %d, want 1 (witness %+v)", a.ShadowedBy, a.ShadowedWitness)
	}
	assertShadowed(t, rules, rules[2], a)
}

// 区域对有方向：反向区域对不影响分析。
func TestAnalyzeZonePairDirection(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "b", DstZone: "a", Protocol: ProtocolANY, Action: ActionDeny},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 65535, Action: ActionAllow},
	}
	results := Analyze(rules)
	a := findAnalysis(t, results, 2)
	if a.Status != StatusEffective {
		t.Fatalf("status = %s, want EFFECTIVE", a.Status)
	}
}

// ANY 规则跨三种协议分析：ICMP 维度被遮蔽，TCP/UDP 维度可达。
func TestAnalyzeAnyProtocolPartial(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolICMP, Action: ActionDeny},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionAllow},
	}
	results := Analyze(rules)
	a := findAnalysis(t, results, 2)
	if a.Status != StatusPartial {
		t.Fatalf("status = %s, want PARTIAL", a.Status)
	}
	if a.ShadowedWitness == nil || a.ShadowedWitness.Protocol != ProtocolICMP {
		t.Fatalf("shadowed witness should be ICMP: %+v", a.ShadowedWitness)
	}
	if a.ReachableWitness == nil || a.ReachableWitness.Protocol == ProtocolICMP {
		t.Fatalf("reachable witness should be TCP or UDP: %+v", a.ReachableWitness)
	}
	assertReachable(t, rules, rules[1], a.ReachableWitness)
	assertShadowed(t, rules, rules[1], a)
}

// 时段共同遮蔽：两条时段互补的规则合起来遮蔽全周规则。
func TestAnalyzeTimeJointShadow(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolUDP, PortStart: 53, PortEnd: 53, Action: ActionDeny, Times: []TimeRange{{Start: 0, End: 5000}}},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolUDP, PortStart: 53, PortEnd: 53, Action: ActionDeny, Times: []TimeRange{{Start: 5000, End: MinutesPerWeek}}},
		{ID: 3, Priority: 3, SrcZone: "a", DstZone: "b", Protocol: ProtocolUDP, PortStart: 53, PortEnd: 53, Action: ActionAllow},
	}
	results := Analyze(rules)
	a := findAnalysis(t, results, 3)
	if a.Status != StatusShadowed {
		t.Fatalf("status = %s, want SHADOWED", a.Status)
	}
	assertShadowed(t, rules, rules[2], a)
}

// 分析结果按执行顺序排列。
func TestAnalyzeResultOrder(t *testing.T) {
	rules := []Rule{
		{ID: 9, Priority: 30, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionAllow},
		{ID: 7, Priority: 10, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionDeny},
		{ID: 8, Priority: 10, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionLog},
	}
	results := Analyze(rules)
	want := []int{7, 8, 9}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	for i, id := range want {
		if results[i].RuleID != id {
			t.Fatalf("results[%d].RuleID = %d, want %d", i, results[i].RuleID, id)
		}
	}
}
