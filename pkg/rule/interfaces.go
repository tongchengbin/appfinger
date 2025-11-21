package rule

// MatchPartGetter 定义了获取匹配部分的函数类型 CaseSensitive 大小写敏感
type MatchPartGetter func(part string, CaseSensitive bool) string
