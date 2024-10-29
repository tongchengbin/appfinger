package rule

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
)
import "github.com/projectdiscovery/gologger"

func ScanRuleDirectory(directory string) (*Finger, error) {
	group := NewFinger()
	// 判断是文件名还是目录
	file, err := os.Stat(directory)
	if err != nil {
		return nil, err
	}
	if file.IsDir() {
		//	scan
		_ = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// 如果是文件，并且扩展名是 .yaml 或 .yml，处理文件
			if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yaml") || strings.HasSuffix(info.Name(), ".yml")) {
				rules, err := LoadRule(path)
				if err != nil {
					return err
				}
				group.AddRules(rules)

			}
			return nil
		})
	} else {
		// 单个文件
		rules, err := LoadRule(directory)
		if err != nil {
			return nil, err
		}
		group.AddRules(rules)
	}
	return group, nil
}
func LoadRule(filename string) ([]*Rule, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		gologger.Warning().Msgf("ReadFile Error:%v", err.Error())
		return nil, err
	}
	var rules []*Rule
	err = yaml.Unmarshal(content, &rules)
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		for _, matcher := range rule.Matchers {
			err := matcher.CompileMatchers()
			if err != nil {
				gologger.Error().Msgf("%s Compile matcher:%s -> %s", filename, err.Error(), rule.Name)
				continue
			}
		}
	}
	return rules, nil

}
