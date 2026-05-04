package wrappers

import (
	"fmt"
	"strings"
	"github.com/gvamaresh/logposesift/internal/registry"
)

// ExecuteDynamicTool safely runs a tool from the registry.
func ExecuteDynamicTool(toolName string, targetPath string) (string, error) {
	tools := registry.GetToolArsenal()
	
	tool, exists := tools[toolName]
	if !exists {
		return "", fmt.Errorf("SECURITY BLOCK: Tool '%s' is not in the approved SIFT registry", toolName)
	}

	// Prepare the arguments safely
	var finalArgs []string
	for _, arg := range tool.FixedArgs {
		if arg == "{TARGET}" {
			finalArgs = append(finalArgs, targetPath)
		} else {
			finalArgs = append(finalArgs, arg)
		}
	}

	fmt.Printf("[*] Security Check Passed: Executing %s %s\n", tool.Binary, strings.Join(finalArgs, " "))
	
	// Use your existing RunCommand executor (with a generous 10-minute timeout for heavy tools)
	output, err := RunCommand(10, tool.Binary, finalArgs...)
	if err != nil {
		return "", fmt.Errorf("tool execution failed: %v\nOutput: %s", err, output)
	}

	return output, nil
}