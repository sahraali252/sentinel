package anomaly

import "testing"

func TestObserveEWMAAndBoundary(t *testing.T) {
	state := State{Mean: 10, Variance: 4, Samples: 20}
	next, z := Observe(state, 17, 0.25)
	if z != 3.5 {
		t.Fatalf("z=%v want 3.5 exact threshold", z)
	}
	if next.Mean != 11.75 || next.Samples != 21 {
		t.Fatalf("unexpected next state: %#v", next)
	}
}
func TestObserveFirstSample(t *testing.T) {
	state, z := Observe(State{}, 8, 0.2)
	if state.Mean != 8 || state.Samples != 1 || z != 0 {
		t.Fatalf("unexpected first observation: %#v z=%v", state, z)
	}
}
