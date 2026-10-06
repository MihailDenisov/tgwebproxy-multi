// Package metrics is a minimal Prometheus text-format registry.
//
// It exists instead of a dependency because the relay needs perhaps a dozen
// series and no push, no histograms and no exemplars. Everything it exports
// is served on the admin listener, which never leaves the loopback: a metrics
// endpoint on the public port would be a fingerprint that undoes the gate.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type kind int

const (
	counter kind = iota
	gauge
)

type series struct {
	name   string
	help   string
	kind   kind
	labels []string
	value  atomic.Int64
}

// Registry holds every series. Series are created on first use and never
// removed: a counter that disappears when it returns to zero is worse than
// useless to whoever is graphing it.
type Registry struct {
	mu   sync.RWMutex
	seen map[string]*series
	meta map[string]metadata
}

type metadata struct {
	help string
	kind kind
}

func New() *Registry {
	r := &Registry{
		seen: make(map[string]*series),
		meta: make(map[string]metadata),
	}
	for _, m := range []struct {
		name string
		help string
		kind kind
	}{
		{"tgwp_sessions_started_total", "Transport sessions accepted.", counter},
		{"tgwp_sessions_active", "Transport sessions currently open.", gauge},
		{"tgwp_streams_opened_total", "MTProto streams opened inside sessions.", counter},
		{"tgwp_streams_active", "MTProto streams currently open.", gauge},
		{"tgwp_bytes_up_total", "Bytes forwarded from clients to Telegram.", counter},
		{"tgwp_bytes_down_total", "Bytes forwarded from Telegram to clients.", counter},
		{"tgwp_upstream_dial_failures_total", "Failed connections to a data centre.", counter},
		{"tgwp_protocol_errors_total", "Sessions dropped for breaking the transport contract.", counter},
		{"tgwp_gate_rejections_total", "Requests answered with the cover site.", counter},
		{"tgwp_transport_messages_total", "Transport messages written towards clients.", counter},
		{"tgwp_coalescable_messages_total", "Messages already queued when another was written, which batching would have collapsed.", counter},
	} {
		r.meta[m.name] = metadata{help: m.help, kind: m.kind}
	}
	return r
}

// Add increases a counter or moves a gauge. Label values are given in pairs.
func (r *Registry) Add(name string, delta int64, labels ...string) {
	r.lookup(name, labels).value.Add(delta)
}

// Value returns the current value of one exact series.
func (r *Registry) Value(name string, labels ...string) int64 {
	key := name + "\x00" + strings.Join(labels, "\x00")
	r.mu.RLock()
	found := r.seen[key]
	r.mu.RUnlock()
	if found == nil {
		return 0
	}
	return found.value.Load()
}

// Sum returns the sum of all series with the given metric name that contain
// every requested label pair. It is useful when a metric has extra labels,
// such as carrier, but management wants a per-client aggregate.
func (r *Registry) Sum(name string, labels ...string) int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var total int64
	for _, s := range r.seen {
		if s.name != name || !hasLabels(s.labels, labels) {
			continue
		}
		total += s.value.Load()
	}
	return total
}

func hasLabels(all, want []string) bool {
	if len(want)%2 != 0 {
		return false
	}
	for i := 0; i+1 < len(want); i += 2 {
		found := false
		for j := 0; j+1 < len(all); j += 2 {
			if all[j] == want[i] && all[j+1] == want[i+1] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (r *Registry) lookup(name string, labels []string) *series {
	key := name + "\x00" + strings.Join(labels, "\x00")

	r.mu.RLock()
	found, ok := r.seen[key]
	r.mu.RUnlock()
	if ok {
		return found
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if found, ok := r.seen[key]; ok {
		return found
	}
	meta := r.meta[name]
	s := &series{name: name, help: meta.help, kind: meta.kind, labels: labels}
	r.seen[key] = s
	return s
}

// WriteTo renders the registry in the Prometheus text exposition format.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.RLock()
	all := make([]*series, 0, len(r.seen))
	for _, s := range r.seen {
		all = append(all, s)
	}
	r.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool {
		if all[i].name != all[j].name {
			return all[i].name < all[j].name
		}
		return strings.Join(all[i].labels, "\x00") < strings.Join(all[j].labels, "\x00")
	})

	var out strings.Builder
	lastName := ""
	for _, s := range all {
		if s.name != lastName {
			kindName := "counter"
			if s.kind == gauge {
				kindName = "gauge"
			}
			fmt.Fprintf(&out, "# HELP %s %s\n# TYPE %s %s\n", s.name, s.help, s.name, kindName)
			lastName = s.name
		}
		fmt.Fprintf(&out, "%s%s %d\n", s.name, renderLabels(s.labels), s.value.Load())
	}
	n, err := io.WriteString(w, out.String())
	return int64(n), err
}

func renderLabels(labels []string) string {
	if len(labels) < 2 {
		return ""
	}
	var out strings.Builder
	out.WriteByte('{')
	for i := 0; i+1 < len(labels); i += 2 {
		if i > 0 {
			out.WriteByte(',')
		}
		out.WriteString(labels[i])
		out.WriteString(`="`)
		out.WriteString(escape(labels[i+1]))
		out.WriteByte('"')
	}
	out.WriteByte('}')
	return out.String()
}

// escape keeps a label value from breaking the line format. Values come from
// the operator's own configuration, but a stray quote would corrupt every
// series in the response, so it is cheap insurance.
func escape(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return replacer.Replace(value)
}
