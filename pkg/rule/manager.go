package rule

import (
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

// RuleManager 规则管理器，实现单例模式和热更新
type RuleManager struct {
	finger       *Finger
	rulePath     string
	lastLoadTime time.Time
	mutex        sync.RWMutex
}

var (
	// 全局单例
	instance *RuleManager
	once     sync.Once
)

// GetRuleManager 获取规则管理器实例
func GetRuleManager() *RuleManager {
	once.Do(func() {
		instance = &RuleManager{}
	})
	return instance
}

// LoadRules 加载规则库
func (m *RuleManager) LoadRules(path string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 加载规则
	finger, err := ScanRuleDirectory(path)
	if err != nil {
		return fmt.Errorf("加载规则库失败: %v", err)
	}

	// 更新规则和路径
	m.finger = finger
	m.rulePath = path
	m.lastLoadTime = time.Now()

	gologger.Info().Msgf("成功加载规则库: %s，规则数量: %d", path, len(m.finger.Rules))
	return nil
}

// GetFinger 获取指纹库
func (m *RuleManager) GetFinger() *Finger {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.finger
}

// ReloadRules 重新加载规则库
func (m *RuleManager) ReloadRules() error {
	if m.rulePath == "" {
		return fmt.Errorf("未设置规则库路径")
	}
	return m.LoadRules(m.rulePath)
}

// GetLastLoadTime 获取最后加载时间
func (m *RuleManager) GetLastLoadTime() time.Time {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.lastLoadTime
}

// IsLoaded 判断规则库是否已加载
func (m *RuleManager) IsLoaded() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.finger != nil
}
