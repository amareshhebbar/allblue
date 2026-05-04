package wrappers

func RunLog2Timeline(storageFile string, targetPath string) (string, error) {
	return RunCommand(60, "log2timeline.py", "--quiet", storageFile, targetPath)
}

func RunPsort(outputCsv string, storageFile string, timeFilter string) (string, error) {
	args := []string{"-o", "l2tcsv", "-w", outputCsv, storageFile}
	if timeFilter != "" {
		args = append(args, timeFilter)
	}
	return RunCommand(30, "psort.py", args...)
}