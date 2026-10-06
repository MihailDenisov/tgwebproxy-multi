package metrics

import (
	"strings"
	"sync"
	"testing"
)

func render(t *testing.T, r *Registry) string {
	t.Helper()
	var out strings.Builder
	if _, err := r.WriteTo(&out); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return out.String()
}

func TestCountersAndLabels(t *testing.T) {
	r := New()
	r.Add("tgwp_bytes_up_total", 100, "domain", "a.example.com", "label", "phone")
	r.Add("tgwp_bytes_up_total", 40, "domain", "a.example.com", "label", "phone")
	r.Add("tgwp_bytes_up_total", 7, "domain", "b.example.com", "label", "laptop")
	r.Add("tgwp_sessions_active", 1, "domain", "a.example.com", "label", "phone")
	r.Add("tgwp_sessions_active", -1, "domain", "a.example.com", "label", "phone")

	got := render(t, r)
	for _, want := range []string{
		"# TYPE tgwp_bytes_up_total counter",
		`tgwp_bytes_up_total{domain="a.example.com",label="phone"} 140`,
		`tgwp_bytes_up_total{domain="b.example.com",label="laptop"} 7`,
		"# TYPE tgwp_sessions_active gauge",
		`tgwp_sessions_active{domain="a.example.com",label="phone"} 0`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// One HELP and TYPE pair per metric name, however many series it has.
	if n := strings.Count(got, "# TYPE tgwp_bytes_up_total"); n != 1 {
		t.Errorf("TYPE repeated %d times for one metric", n)
	}
}

// A gauge that returned to zero must keep its series: a graph with a gap is
// worse than one showing zero.
func TestSeriesSurviveReturningToZero(t *testing.T) {
	r := New()
	r.Add("tgwp_streams_active", 1, "domain", "a.example.com", "label", "phone")
	r.Add("tgwp_streams_active", -1, "domain", "a.example.com", "label", "phone")
	if !strings.Contains(render(t, r), `tgwp_streams_active{domain="a.example.com",label="phone"} 0`) {
		t.Error("the series disappeared when it reached zero")
	}
}

func TestLabelValuesAreEscaped(t *testing.T) {
	r := New()
	r.Add("tgwp_sessions_started_total", 1, "domain", "a.example.com", "label", `we"ird\one`)
	got := render(t, r)
	if !strings.Contains(got, `label="we\"ird\\one"`) {
		t.Errorf("label not escaped:\n%s", got)
	}
	// Whatever the label contains, the output stays one line per series.
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Count(line, " ") != 1 {
			t.Errorf("line does not look like one sample: %q", line)
		}
	}
}

func TestConcurrentAddIsSafe(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.Add("tgwp_bytes_down_total", 1, "domain", "a.example.com", "label", "phone")
			}
		}()
	}
	wg.Wait()
	if !strings.Contains(render(t, r), `tgwp_bytes_down_total{domain="a.example.com",label="phone"} 5000`) {
		t.Errorf("lost counts under concurrency:\n%s", render(t, r))
	}
}
