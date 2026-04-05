package ledger_test

import (
	"testing"

	"go.sia.tech/ledger-go"
)

func TestLedger(t *testing.T) {
	device, err := ledger.Open()
	if err != nil {
		t.Fatal(err)
	}

	addr, err := device.GetAddress(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Address:", addr)
}
