package main

import (
	"errors"
	"testing"
)

func TestOptionalDays(t *testing.T) {
	v, err := optionalDays("remember-me-max-days", -1)
	if err != nil || v != nil {
		t.Fatalf("flag not given: want nil, nil; got %v, %v", v, err)
	}
	v, err = optionalDays("remember-me-max-days", 30)
	if err != nil || v == nil || *v != 30 {
		t.Fatalf("30: want 30; got %v, %v", v, err)
	}
	for _, bad := range []int{0, 366} {
		var ue usageError
		if _, err := optionalDays("remember-me-max-days", bad); !errors.As(err, &ue) {
			t.Fatalf("%d: want a usage error, got %v", bad, err)
		}
	}
}
