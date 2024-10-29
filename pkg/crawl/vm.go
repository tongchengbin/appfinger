package crawl

import (
	"fmt"
	"github.com/robertkrimen/otto"
	"time"
)

// 执行 JavaScript 脚本并设置超时时间
func runScriptWithTimeout(vm *otto.Otto, script string, timeout time.Duration) error {
	done := make(chan error, 1)

	go func() {
		_, err := vm.Run(script)
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("script execution timed out")
	}
}
