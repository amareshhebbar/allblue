package wrappers

import (
	"fmt"
	"strings"
	"time"

	"github.com/gvamaresh/allblue/internal/registry"
)

func RunRegistryTool(toolKey string, targetValue string) (string, error) {
	arsenal := registry.GetToolArsenal()
	tool, ok := arsenal[toolKey]
	if !ok {
		return "", fmt.Errorf("tool %q not found in registry; check internal/registry/sift_tools.go", toolKey)
	}
	if targetValue == "" {
		return "", fmt.Errorf("tool %q requires a target value for param %q", toolKey, tool.TargetParam)
	}
	if containsShellMeta(targetValue) {
		return "", fmt.Errorf("target value for tool %q contains disallowed shell metacharacters", toolKey)
	}
	args := substituteTarget(tool.FixedArgs, targetValue)
	timeout := toolTimeout(toolKey)

	output, err := SafeExec(tool.Binary, args, timeout)
	if err != nil {
		return "", fmt.Errorf("[%s] %v", toolKey, err)
	}
	return output, nil
}

func RunRegistryToolMultiTarget(toolKey string, params map[string]string) (string, error) {
	arsenal := registry.GetToolArsenal()
	tool, ok := arsenal[toolKey]
	if !ok {
		return "", fmt.Errorf("tool %q not found in registry", toolKey)
	}
	for k, v := range params {
		if containsShellMeta(v) {
			return "", fmt.Errorf("param %q for tool %q contains disallowed shell metacharacters", k, toolKey)
		}
	}

	args := make([]string, len(tool.FixedArgs))
	copy(args, tool.FixedArgs)
	for k, v := range params {
		placeholder := "{" + strings.ToUpper(k) + "}"
		for i, arg := range args {
			args[i] = strings.ReplaceAll(arg, placeholder, v)
			args[i] = strings.ReplaceAll(args[i], "{TARGET}", v) 
		}
		_ = placeholder
	}

	if primary, ok := params[tool.TargetParam]; ok {
		args = substituteTarget(args, primary)
	}

	timeout := toolTimeout(toolKey)
	output, err := SafeExec(tool.Binary, args, timeout)
	if err != nil {
		return "", fmt.Errorf("[%s] %v", toolKey, err)
	}
	return output, nil
}

func ToolExists(toolKey string) bool {
	_, ok := registry.GetToolArsenal()[toolKey]
	return ok
}

func ListTools() []string {
	arsenal := registry.GetToolArsenal()
	keys := make([]string, 0, len(arsenal))
	for k := range arsenal {
		keys = append(keys, k)
	}
	return keys
}


func substituteTarget(args []string, target string) []string {
	result := make([]string, len(args))
	for i, arg := range args {
		result[i] = strings.ReplaceAll(arg, "{TARGET}", target)
	}
	return result
}

func toolTimeout(toolKey string) time.Duration {
	switch {
	case strings.HasPrefix(toolKey, "plaso_log2timeline"):
		return 120 
	case strings.HasPrefix(toolKey, "plaso_"):
		return 30
	case strings.HasPrefix(toolKey, "vol_"):
		return 10
	case strings.HasPrefix(toolKey, "tsk_"):
		return 5
	case strings.HasPrefix(toolKey, "pcap_"):
		return 15
	default:
		return 5
	}
}