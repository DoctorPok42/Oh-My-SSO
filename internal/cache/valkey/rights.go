package valkey

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
)

type RightsEpoch struct {
	client valkey.Client
	now    func() time.Time
}

// rightsEpochKey: deleting it (valkey-cli DEL omsso:admin:rights_epoch)
// makes the Admin API re-check every admin token's permissions in the
// database until the console refreshes them.
const rightsEpochKey = "omsso:admin:rights_epoch"

// NewRightsEpoch returns the Valkey implementation of adminapi.RightsEpoch.
func NewRightsEpoch(client valkey.Client) *RightsEpoch {
	return &RightsEpoch{client: client, now: time.Now}
}

var readEpoch = valkey.NewLuaScript(`
local v = redis.call('GET', KEYS[1])
if v then return v end
redis.call('SET', KEYS[1], ARGV[1])
return ARGV[1]
`)

// raiseEpoch stores ARGV[1] only if it is later than the stored time: two
// processes with slightly different clocks never move it backwards.
var raiseEpoch = valkey.NewLuaScript(`
local v = tonumber(redis.call('GET', KEYS[1]) or '0')
if tonumber(ARGV[1]) > v then
  redis.call('SET', KEYS[1], ARGV[1])
end
return 1
`)

// LastChange implements adminapi.RightsEpoch.
func (e *RightsEpoch) LastChange(ctx context.Context) (time.Time, error) {
	ms, err := readEpoch.Exec(ctx, e.client, []string{rightsEpochKey},
		[]string{strconv.FormatInt(e.now().UnixMilli(), 10)}).AsInt64()
	if err != nil {
		return time.Time{}, fmt.Errorf("rights epoch: read: %w", err)
	}
	return time.UnixMilli(ms), nil
}

// Changed implements adminapi.RightsEpoch.
func (e *RightsEpoch) Changed(ctx context.Context, t time.Time) error {
	if err := raiseEpoch.Exec(ctx, e.client, []string{rightsEpochKey},
		[]string{strconv.FormatInt(t.UnixMilli(), 10)}).Error(); err != nil {
		return fmt.Errorf("rights epoch: record: %w", err)
	}
	return nil
}
