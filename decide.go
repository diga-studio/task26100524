package bastiongrid

// Decision 报文经过规则集后的判定结果。
type Decision struct {
	Action Action // 最终动作；无终止规则时为默认 DENY
	RuleID int    // 终止规则的编号；无终止规则时为 -1
	Logged []int  // 依次命中的 LOG 规则编号
}

// Decide 模拟报文按执行顺序经过规则集，返回最终判定。
// 用于验证分析给出的见证报文可复现。
func Decide(rules []Rule, p Packet) Decision {
	dec := Decision{Action: ActionDeny, RuleID: -1}
	for _, r := range executionOrder(rules) {
		if !r.Matches(p) {
			continue
		}
		switch r.Action {
		case ActionLog:
			dec.Logged = append(dec.Logged, r.ID)
		case ActionAllow, ActionDeny:
			dec.Action = r.Action
			dec.RuleID = r.ID
			return dec
		}
	}
	return dec
}
