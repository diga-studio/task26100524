package bastiongrid

import (
	"reflect"
	"testing"
)

func TestEvaluatePriorityAndIDOrder(t *testing.T) {
	rules := []Rule{
		{ID: 2, Priority: 10, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionAllow},
		{ID: 1, Priority: 10, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionDeny},
		{ID: 3, Priority: 5, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 80, PortEnd: 80, Action: ActionAllow},
	}
	pkt := Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, Port: 80, Minute: 0}

	// 优先级 5 的规则最先执行。
	if d := Evaluate(rules, pkt); d.Verdict != ActionAllow || d.RuleID != 3 {
		t.Fatalf("priority order: got %+v", d)
	}
	// 去掉优先级 5 的规则后，同优先级按编号升序，ID 1 先执行。
	if d := Evaluate(rules[:2], pkt); d.Verdict != ActionDeny || d.RuleID != 1 {
		t.Fatalf("id tie-break: got %+v", d)
	}
}

func TestEvaluateLogContinues(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionLog},
		{ID: 2, Priority: 2, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 0, PortEnd: 65535, Action: ActionLog},
		{ID: 3, Priority: 3, SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443, Action: ActionAllow},
	}
	pkt := Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, Port: 443, Minute: 5000}
	d := Evaluate(rules, pkt)
	if d.Verdict != ActionAllow || d.RuleID != 3 {
		t.Fatalf("verdict: got %+v", d)
	}
	if !reflect.DeepEqual(d.Logged, []int{1, 2}) {
		t.Fatalf("logged: got %v", d.Logged)
	}
}

func TestEvaluateDefaultDeny(t *testing.T) {
	d := Evaluate(nil, Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolUDP, Port: 53, Minute: 0})
	if d.Verdict != ActionDeny || d.RuleID != -1 || len(d.Logged) != 0 {
		t.Fatalf("default deny: got %+v", d)
	}
}

func TestEvaluateZonePairDirection(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionAllow},
	}
	// 反向区域对不匹配。
	pkt := Packet{SrcZone: "b", DstZone: "a", Protocol: ProtocolTCP, Port: 1, Minute: 0}
	if d := Evaluate(rules, pkt); d.Verdict != ActionDeny || d.RuleID != -1 {
		t.Fatalf("reversed zone pair must not match: got %+v", d)
	}
}

func TestEvaluatePortRangeInclusive(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolUDP, PortStart: 100, PortEnd: 200, Action: ActionAllow},
	}
	for _, port := range []int{100, 150, 200} {
		pkt := Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolUDP, Port: port, Minute: 0}
		if d := Evaluate(rules, pkt); d.Verdict != ActionAllow {
			t.Fatalf("port %d should match: got %+v", port, d)
		}
	}
	for _, port := range []int{99, 201} {
		pkt := Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolUDP, Port: port, Minute: 0}
		if d := Evaluate(rules, pkt); d.Verdict != ActionDeny {
			t.Fatalf("port %d should not match: got %+v", port, d)
		}
	}
}

func TestEvaluateTimeRangeHalfOpen(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionAllow, Times: []TimeRange{{Start: 10, End: 20}}},
	}
	pkt := Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, Port: 1, Minute: 10}
	if d := Evaluate(rules, pkt); d.Verdict != ActionAllow {
		t.Fatalf("start minute inclusive: got %+v", d)
	}
	pkt.Minute = 20
	if d := Evaluate(rules, pkt); d.Verdict != ActionDeny {
		t.Fatalf("end minute exclusive: got %+v", d)
	}
	pkt.Minute = 10079
	if d := Evaluate(rules, pkt); d.Verdict != ActionDeny {
		t.Fatalf("outside window: got %+v", d)
	}
}

func TestEvaluateAnyAndICMP(t *testing.T) {
	rules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolANY, Action: ActionAllow},
	}
	// ANY 匹配 ICMP 且不限制端口。
	pkt := Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolICMP, Minute: 0}
	if d := Evaluate(rules, pkt); d.Verdict != ActionAllow || d.RuleID != 1 {
		t.Fatalf("ANY should match ICMP: got %+v", d)
	}
	// ICMP 规则忽略端口字段。
	icmpRules := []Rule{
		{ID: 1, Priority: 1, SrcZone: "a", DstZone: "b", Protocol: ProtocolICMP, Action: ActionDeny},
	}
	if d := Evaluate(icmpRules, pkt); d.Verdict != ActionDeny || d.RuleID != 1 {
		t.Fatalf("ICMP rule should match: got %+v", d)
	}
	// ICMP 规则不匹配 TCP 报文。
	tcpPkt := Packet{SrcZone: "a", DstZone: "b", Protocol: ProtocolTCP, Port: 0, Minute: 0}
	if d := Evaluate(icmpRules, tcpPkt); d.Verdict != ActionDeny || d.RuleID != -1 {
		t.Fatalf("ICMP rule must not match TCP: got %+v", d)
	}
}
