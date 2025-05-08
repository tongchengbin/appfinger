package rule

// BannerInfo 定义Banner信息接口
// 这个接口允许我们在不依赖crawl包的情况下处理Banner数据
type BannerInfo interface {
	// GetMatchPart 获取匹配部分
	GetMatchPart(part string) string
	// GetStatusCode 获取状态码
	GetStatusCode() int
	// GetURI 获取URI
	GetURI() string
}

// DefaultRuleMatcher 默认规则匹配器实现
type DefaultRuleMatcher struct {
	finger *Finger
}

// NewDefaultRuleMatcher 创建默认规则匹配器
func NewDefaultRuleMatcher(finger *Finger) *DefaultRuleMatcher {
	if finger == nil {
		// 尝试从RuleManager获取finger
		ruleManager := GetRuleManager()
		if ruleManager != nil {
			finger = ruleManager.GetFinger()
		}
	}

	return &DefaultRuleMatcher{
		finger: finger,
	}
}

// MatchRuleResult 定义规则匹配的结果
type MatchRuleResult struct {
	// Fingerprints 匹配到的指纹
	Fingerprints map[string]map[string]string
	// Plugins 需要执行的插件
	Plugins []*Plugin
}

// MatchRule 执行规则匹配
// 返回匹配到的指纹和需要执行的插件列表
func (m *DefaultRuleMatcher) MatchRule(bannerInfo BannerInfo) (MatchRuleResult, error) {
	if m.finger == nil {
		return MatchRuleResult{
			Fingerprints: make(map[string]map[string]string),
			Plugins:      nil,
		}, nil
	}

	// 匹配指纹
	fingerprints := map[string]map[string]string{}
	// 需要执行的插件列表
	var pluginsToExecute []*Plugin

	// 创建匹配部分获取函数
	getMatchPart := func(part string) string {
		return bannerInfo.GetMatchPart(part)
	}

	// 遍历所有协议类型的规则
	for _, rules := range m.finger.Rules {
		// 遍历每个规则
		for _, r := range rules {
			matched, _ := r.Match(getMatchPart)

			if matched {
				// 如果匹配成功，添加到指纹映射
				if _, ok := fingerprints[r.Service]; !ok {
					fingerprints[r.Service] = make(map[string]string)
				}
				// 使用规则名称作为版本，因为Rule结构体没有Version字段
				fingerprints[r.Service][r.Name] = r.Name

				// 如果规则有插件，添加到插件列表
				if len(r.Plugins) > 0 {
					pluginsToExecute = append(pluginsToExecute, r.Plugins...)
				}
			}
		}
	}

	return MatchRuleResult{
		Fingerprints: fingerprints,
		Plugins:      pluginsToExecute,
	}, nil
}
