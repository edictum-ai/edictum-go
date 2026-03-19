package yaml

import (
	"fmt"

	"github.com/edictum-ai/edictum-go/internal/deepcopy"
)

// CompositionOverride records a contract replaced during composition.
type CompositionOverride struct {
	ContractID     string
	OverriddenBy   string // Source label of the winning layer.
	OriginalSource string // Source label of the replaced layer.
}

// ObserveContract records a contract added as observe-mode via observe_alongside.
type ObserveContract struct {
	ContractID     string
	EnforcedSource string
	ObservedSource string
}

// CompositionReport describes what happened during composition.
type CompositionReport struct {
	Overrides []CompositionOverride
	Observes  []ObserveContract
}

// ComposedBundle is the result of composing multiple bundles.
type ComposedBundle struct {
	Bundle map[string]any
	Report CompositionReport
}

// ComposeBundles merges multiple parsed bundle dicts left-to-right.
// Each entry is (bundle, sourceLabel). Later layers have higher priority.
func ComposeBundles(bundles ...BundleEntry) (ComposedBundle, error) {
	if len(bundles) == 0 {
		return ComposedBundle{}, fmt.Errorf("ComposeBundles requires at least one bundle")
	}

	if len(bundles) == 1 {
		return ComposedBundle{
			Bundle: deepcopy.Map(bundles[0].Data),
			Report: CompositionReport{},
		}, nil
	}

	merged := deepcopy.Map(bundles[0].Data)
	sources := map[string]string{}
	for _, c := range contractList(merged) {
		if id, ok := c["id"].(string); ok {
			sources[id] = bundles[0].Label
		}
	}

	var overrides []CompositionOverride
	var observes []ObserveContract

	for _, entry := range bundles[1:] {
		if isObserveAlongside(entry.Data) {
			mergeObserveAlongside(merged, entry.Data, entry.Label, sources, &observes)
		} else {
			mergeStandard(merged, entry.Data, entry.Label, sources, &overrides)
		}
	}

	return ComposedBundle{
		Bundle: merged,
		Report: CompositionReport{Overrides: overrides, Observes: observes},
	}, nil
}

// BundleEntry pairs a parsed bundle with its source label.
type BundleEntry struct {
	Data  map[string]any
	Label string
}

func isObserveAlongside(data map[string]any) bool {
	v, ok := data["observe_alongside"].(bool)
	return ok && v
}

func contractList(bundle map[string]any) []map[string]any {
	raw, ok := bundle["contracts"].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func mergeStandard(
	merged, layer map[string]any,
	label string,
	sources map[string]string,
	overrides *[]CompositionOverride,
) {
	// defaults.mode: later wins
	if defaults, ok := layer["defaults"].(map[string]any); ok {
		md := ensureMap(merged, "defaults")
		if mode, ok := defaults["mode"]; ok {
			md["mode"] = mode
		}
		if env, ok := defaults["environment"]; ok {
			md["environment"] = env
		}
	}

	// limits: later wins entirely
	if limits, ok := layer["limits"]; ok {
		merged["limits"] = deepcopy.Value(limits)
	}

	// tools: deep merge
	if tools, ok := layer["tools"].(map[string]any); ok {
		mt := ensureMap(merged, "tools")
		for k, v := range tools {
			mt[k] = deepcopy.Value(v)
		}
	}

	// metadata: deep merge
	if meta, ok := layer["metadata"].(map[string]any); ok {
		mm := ensureMap(merged, "metadata")
		for k, v := range meta {
			mm[k] = deepcopy.Value(v)
		}
	}

	// observability: later wins entirely
	if obs, ok := layer["observability"]; ok {
		merged["observability"] = deepcopy.Value(obs)
	}

	// contracts: same ID replaces, unique appends
	layerContracts := contractList(layer)
	if len(layerContracts) == 0 {
		return
	}
	existingByID := map[string]int{}
	existing := contractList(merged)
	for i, c := range existing {
		if id, ok := c["id"].(string); ok {
			existingByID[id] = i
		}
	}

	raw, _ := merged["contracts"].([]any)
	for _, c := range layerContracts {
		cid, _ := c["id"].(string)
		cp := deepcopy.Map(c)
		if idx, found := existingByID[cid]; found {
			orig := sources[cid]
			*overrides = append(*overrides, CompositionOverride{
				ContractID: cid, OverriddenBy: label, OriginalSource: orig,
			})
			raw[idx] = cp
			sources[cid] = label
		} else {
			raw = append(raw, cp)
			existingByID[cid] = len(raw) - 1
			sources[cid] = label
		}
	}
	merged["contracts"] = raw
}

func mergeObserveAlongside(
	merged, layer map[string]any,
	label string,
	sources map[string]string,
	observes *[]ObserveContract,
) {
	for _, c := range contractList(layer) {
		cid, _ := c["id"].(string)
		observeID := cid + ":candidate"
		cp := deepcopy.Map(c)
		cp["id"] = observeID
		cp["mode"] = "observe"
		cp["_observe"] = true

		raw, _ := merged["contracts"].([]any)
		merged["contracts"] = append(raw, cp)

		*observes = append(*observes, ObserveContract{
			ContractID: cid, EnforcedSource: sources[cid], ObservedSource: label,
		})
	}

	// Deep merge tools + metadata from observe_alongside layers
	if tools, ok := layer["tools"].(map[string]any); ok {
		mt := ensureMap(merged, "tools")
		for k, v := range tools {
			mt[k] = deepcopy.Value(v)
		}
	}
	if meta, ok := layer["metadata"].(map[string]any); ok {
		mm := ensureMap(merged, "metadata")
		for k, v := range meta {
			mm[k] = deepcopy.Value(v)
		}
	}
}

func ensureMap(m map[string]any, key string) map[string]any {
	if sub, ok := m[key].(map[string]any); ok {
		return sub
	}
	sub := map[string]any{}
	m[key] = sub
	return sub
}
