package transforms

// CompiledExemptions is the compiled baseline: an entry must be an exact field path naming
// a field that structurally cannot carry a user secret. Detector-scoped, so the pattern
// packs still scan these fields. The copy is fresh, since callers merge served additions in.
func CompiledExemptions() map[string][]string {
	return map[string][]string{
		"claude-code": {
			// The record spine: redact any of these and the DAG dies.
			"uuid", "parentUuid", "logicalParentUuid", "sessionId", "agentId",
			"message.id", "requestId", "promptId", "interruptedMessageId",
			// The session slug ("sleepy-mochi") trips the backstop; path-user still rewrites it.
			"slug",
			// The spawn-tree and tool-call joins, one id as each record kind spells it.
			"message.content[].id", "message.content[].tool_use_id", "toolUseResult.tool_use_id",
			"toolUseResult.results[].tool_use_id", "toolUseId", "sourceToolUseID", "attachment.toolUseID",
			// A filesystem path, and the source of the per-repository dimension downstream.
			"cwd",
		},
		"codex": {
			// The rollout's tool-call join id (call_…): codex's tool_use_id.
			"payload.call_id",
		},
		"cursor": {
			"composerId", "bubbleId", "checkpointId", "requestId",
			// A hex-encoded image, a declared opaque payload the backstop would destroy.
			"content[].image.hex",
		},
		"project-map": {
			// Paths carrying __USER__, which ADDS entropy. Inert while the inventory is raw-text
			// scanned, so a later jsonl sniff cannot silently expose them to the backstop.
			"cwd", "project_dir",
		},
		"*": {"timestamp", "version"},
	}
}
