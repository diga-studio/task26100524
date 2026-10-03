package bastiongrid

import (
	"math/rand"
	"testing"
)

// 在小规模离散空间上暴力枚举全部报文，交叉验证 Analyze 的判定与见证。
func TestAnalyzeAgainstBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	protocols := []Protocol{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolANY}
	actions := []Action{ActionAllow, ActionDeny, ActionLog}

	for trial := 0; trial < 200; trial++ {
		n := 1 + rng.Intn(5)
		rules := make([]Rule, n)
		for i := range rules {
			pLo := rng.Intn(8)
			pHi := pLo + rng.Intn(8-pLo)
			// 所有规则都限定在 [0,16) 分钟内，与暴力枚举的空间一致。
			start := rng.Intn(16)
			ivs := []TimeInterval{{Start: start, End: start + 1 + rng.Intn(16-start)}}
			rules[i] = Rule{
				ID:        i + 1,
				Priority:  rng.Intn(4),
				SrcZone:   "a",
				DstZone:   "b",
				Protocol:  protocols[rng.Intn(len(protocols))],
				PortStart: pLo,
				PortEnd:   pHi,
				Action:    actions[rng.Intn(len(actions))],
				Intervals: ivs,
			}
		}

		res := Analyze(rules)
		ordered := executionOrder(rules)

		// 暴力计算每条规则的可达/被遮蔽报文存在性。
		bruteReach := map[int]bool{}
		bruteShadow := map[int]bool{}
		for _, target := range ordered {
			for _, proto := range []Protocol{ProtocolTCP, ProtocolUDP, ProtocolICMP} {
				for port := 0; port < 8; port++ {
					if proto == ProtocolICMP && port > 0 {
						continue
					}
					for minute := 0; minute < 16; minute++ {
						pkt := Packet{SrcZone: "a", DstZone: "b", Protocol: proto, Port: port, WeekMinute: minute}
						if !target.Matches(pkt) {
							continue
						}
						shadowed := false
						for _, other := range ordered {
							if other.ID == target.ID {
								break
							}
							if terminates(other.Action) && other.Matches(pkt) {
								shadowed = true
								break
							}
						}
						if shadowed {
							bruteShadow[target.ID] = true
						} else {
							bruteReach[target.ID] = true
						}
					}
				}
			}
		}

		for _, ra := range res.Rules {
			reach, shadow := bruteReach[ra.RuleID], bruteShadow[ra.RuleID]
			want := VerdictPartiallyShadowed
			switch {
			case !shadow:
				want = VerdictFullyEffective
			case !reach:
				want = VerdictFullyShadowed
			}
			if ra.Verdict != want {
				t.Fatalf("trial %d rule %d: verdict = %v, want %v (rules=%+v)", trial, ra.RuleID, ra.Verdict, want, rules)
			}
			if (ra.ReachableWitness != nil) != reach {
				t.Fatalf("trial %d rule %d: reachable witness presence mismatch", trial, ra.RuleID)
			}
			if (ra.ShadowedWitness != nil) != shadow {
				t.Fatalf("trial %d rule %d: shadowed witness presence mismatch", trial, ra.RuleID)
			}
			// 见证必须可复现。
			if ra.ReachableWitness != nil {
				dec := Decide(rules, *ra.ReachableWitness)
				for _, r := range ordered {
					if r.ID == ra.RuleID {
						if terminates(r.Action) && (dec.RuleID != ra.RuleID) {
							t.Fatalf("trial %d rule %d: reachable witness terminated by %d", trial, ra.RuleID, dec.RuleID)
						}
						break
					}
					if terminates(r.Action) && dec.RuleID == r.ID {
						t.Fatalf("trial %d rule %d: reachable witness blocked by earlier %d", trial, ra.RuleID, r.ID)
					}
				}
			}
			if ra.ShadowedWitness != nil {
				dec := Decide(rules, *ra.ShadowedWitness)
				if dec.RuleID != ra.ShadowedBy {
					t.Fatalf("trial %d rule %d: shadowed witness terminated by %d, ShadowedBy = %d",
						trial, ra.RuleID, dec.RuleID, ra.ShadowedBy)
				}
				if dec.RuleID == ra.RuleID || dec.RuleID == -1 {
					t.Fatalf("trial %d rule %d: shadowed witness should be terminated earlier", trial, ra.RuleID)
				}
			}
		}
	}
}
