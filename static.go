package appfinger

import (
	"embed"
	"os"
	"path/filepath"
	"strings"
)

//go:embed app/*
var RulesFiles embed.FS

func LoadDirectoryRule(dir string) []string {
	var contents []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// 如果是文件，并且扩展名是 .yaml 或 .yml，处理文件
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yaml") || strings.HasSuffix(info.Name(), ".yml")) {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			contents = append(contents, string(content))
		}
		return nil
	})
	return contents
}
