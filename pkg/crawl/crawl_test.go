package crawl

import (
	"context"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCrawl(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	crawl := NewCrawler(DefaultOption())
	banner, err := crawl.GetBanner(context.Background(), "https://www.hackerone.com")
	assert.NoError(t, err)
	assert.NotNil(t, banner)
	assert.Equal(t, banner.StatusCode, 200)
}
