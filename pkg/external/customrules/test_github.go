package customrules

import (
	"context"
	"testing"
)

func TestGithub(t *testing.T) {
	DefaultProvider.Download(context.Background(), "/tmp")
}
