package runner

import (
	"context"
	"github.com/tongchengbin/appfinger/pkg/external/customrules"
)

func UpdateRule() {
	customrules.DefaultProvider.Update(context.Background(), GetDefaultDirectory())
	return
}
