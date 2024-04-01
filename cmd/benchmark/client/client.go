package main

import (
	"fmt"
	"github.com/remeh/sizedwaitgroup"
	"github.com/tongchengbin/appfinger/pkg/finger"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

func report() {
	var maxMemory uint64
	// 当内存占用达到最高点时触发生成内存分析报告
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	// 比较当前内存占用与已记录的最高内存占用
	maxMemory = memStats.Alloc
	log.Printf("Peak memory usage: %d bytes", maxMemory)
	f, err := os.Create("m2.prof")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if err := pprof.WriteHeapProfile(f); err != nil {
		log.Fatal(err)
	}
}

func main() {
	go func() {
		log.Println(http.ListenAndServe(":6060", nil))
	}()

	wg := sizedwaitgroup.New(32)
	app := finger.New(&finger.Options{})
	cnt := 1
	t1 := time.Now().Unix()
	for t := 0; t < 128; t++ {
		wg.Add()
		go func() {
			defer wg.Done()
			for cnt < 10000 {
				_, _ = app.MatchURI("http://127.0.0.1:8080")
				cnt += 1
				if cnt == 9000 {
					report()
				}
			}
		}()
	}
	wg.Wait()
	t2 := time.Now().Unix()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	totalAllocatedMemory := memStats.TotalAlloc / 1024 / 1024 // 转换为MB
	fmt.Printf("Total allocated memory: %d KB\n", totalAllocatedMemory)
	println("TIME:", t2-t1)
}
