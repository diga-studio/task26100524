# bastiongrid

BastionGrid 防火墙规则生效性分析库（Go）。纯内存实现，由上层直接调用，无任何外部服务依赖。

## 功能

- 按（优先级, 编号）确定规则执行顺序；`ALLOW`/`DENY` 终止匹配，`LOG` 记录后继续，无终止规则时默认 `DENY`。
- 对每条规则判定：完全有效 / 完全遮蔽 / 部分遮蔽（相同动作也会造成遮蔽，`LOG` 不遮蔽）。
- 可达部分与被遮蔽部分各提供一个可复现的见证报文；被遮蔽见证指出实际终止它的较早规则。

## 使用

```go
rules := []bastiongrid.Rule{ /* ... */ }
res := bastiongrid.Analyze(rules)
for _, ra := range res.Rules {
    fmt.Println(ra.RuleID, ra.Verdict, ra.ReachableWitness, ra.ShadowedWitness, ra.ShadowedBy)
}

// 模拟单个报文的判定，验证见证可复现
dec := bastiongrid.Decide(rules, packet)
```

## 测试

```sh
go test ./...
```

包含两个关键场景：多条较早规则合并完全遮蔽后续规则；仅留 1 分钟 × 1 端口缺口的部分遮蔽（可达见证落在缺口内）。另有随机化属性测试，与暴力枚举交叉验证判定与见证。
