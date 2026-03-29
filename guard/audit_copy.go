package guard

func deepCopyRecords(records []map[string]any) []map[string]any {
	if records == nil {
		return nil
	}
	out := make([]map[string]any, len(records))
	for i, record := range records {
		out[i] = deepCopyRecord(record)
	}
	return out
}

func deepCopyRecord(record map[string]any) map[string]any {
	cp := make(map[string]any, len(record))
	for k, v := range record {
		cp[k] = deepCopyAny(v)
	}
	return cp
}

func deepCopyAny(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyRecord(val)
	case []any:
		cp := make([]any, len(val))
		for i, item := range val {
			cp[i] = deepCopyAny(item)
		}
		return cp
	default:
		return v
	}
}
