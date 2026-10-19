package module

import (
	"context"
	"reflect"
	"testing"
)

func TestMapChannels(t *testing.T) {
	ctx := context.Background()
	if got := MapChannels(ctx, []int64{1, 2}); !reflect.DeepEqual(got, []int64{1, 2}) {
		t.Fatalf("without map: %v", got)
	}
	ctx = WithChannelMap(ctx, map[int64]int64{1: 7, 3: 9})
	if got := MapChannels(ctx, []int64{1, 2, 3}); !reflect.DeepEqual(got, []int64{7, 9}) {
		t.Fatalf("mapped: %v", got)
	}
	if got := MapChannels(ctx, nil); got != nil {
		t.Fatalf("nil stays nil: %v", got)
	}
}
