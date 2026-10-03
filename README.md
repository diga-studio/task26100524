# bastiongrid

BastionGrid 防火墙规则生效性分析库（纯内存，无外部依赖，Go 1.27+）。

## 功能

- `Evaluate(rules, pkt)`：按执行顺序（优先级升序，同优先级按编号升序）评估单个报文。
  命中 `ALLOW`/`DENY` 立即终止；命中 `LOG` 记录编号并继续；无终止规则时默认 `DENY`。
- `Analyze(rules)`：对每条规则判定生效性，并给出可复现的见证报文。
  - `EFFECTIVE`：匹配的全部报文都能执行到它；
  - `SHADOWED`：全部被较早的终止规则拦下（支持多条规则联合遮蔽的精确判定）；
  - `PARTIAL`：部分可达、部分被遮蔽。
  - 可达部分与被遮蔽部分各提供一个具体报文作为见证（非空时）；
    被遮蔽见证的 `ShadowedBy` 指向实际终止它的较早规则。

## 模型约定

- 区域对有方向，按区域标识精确匹配；协议为 `TCP`/`UDP`/`ICMP`，规则可用 `ANY`（匹配三种协议且不限端口）。
- 端口范围包含两端（0–65535），仅对具体 `TCP`/`UDP` 规则有效；`ICMP` 无端口。
- 生效时段为 UTC 周分钟的半开区间 `[Start, End)`，0 为周一 00:00，`MinutesPerWeek`（10080）为下周一 00:00；空时段表示全周。
- `LOG` 不遮蔽后续规则；相同动作也会造成遮蔽。

## 示例

```go
rules := []bastiongrid.Rule{
    {ID: 1, Priority: 10, SrcZone: "dmz", DstZone: "core",
     Protocol: bastiongrid.ProtocolTCP, PortStart: 0, PortEnd: 65535, Action: bastiongrid.ActionDeny},
    {ID: 2, Priority: 20, SrcZone: "dmz", DstZone: "core",
     Protocol: bastiongrid.ProtocolTCP, PortStart: 443, PortEnd: 443, Action: bastiongrid.ActionAllow},
}
for _, a := range bastiongrid.Analyze(rules) {
    fmt.Printf("rule %d: %s (shadowedBy=%d)\n", a.RuleID, a.Status, a.ShadowedBy)
}
// rule 2 被判为 SHADOWED，ShadowedWitness 给出一个被规则 1 实际拦截的报文。
```

## 测试

```sh
go test ./...
```
