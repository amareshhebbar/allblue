package registry

import "fmt"

// SiftTool represents a strictly typed, whitelisted command allowed on the system.
type SiftTool struct {
	Name        string
	Description string
	Binary      string
	FixedArgs   []string
	TargetParam string // The name of the parameter the AI must provide (e.g., "target_file")
}

// GetToolArsenal returns our massive list of allowed DFIR tools
func GetToolArsenal() map[string]SiftTool {
	return map[string]SiftTool{
		// ==========================================
		// VOLATILITY 3 (MEMORY FORENSICS)
		// ==========================================
		"vol_windows_info":      {Name: "vol_windows_info", Description: "Extracts OS info from memory.", Binary: "vol", FixedArgs: []string{"-f", "{TARGET}", "windows.info"}, TargetParam: "dump_path"},
		"vol_windows_pslist":    {Name: "vol_windows_pslist", Description: "Lists running processes.", Binary: "vol", FixedArgs: []string{"-f", "{TARGET}", "windows.pslist"}, TargetParam: "dump_path"},
		"vol_windows_pstree":    {Name: "vol_windows_pstree", Description: "Shows parent/child process relationships.", Binary: "vol", FixedArgs: []string{"-f", "{TARGET}", "windows.pstree"}, TargetParam: "dump_path"},
		"vol_windows_netscan":   {Name: "vol_windows_netscan", Description: "Scans for network connections and C2 IPs.", Binary: "vol", FixedArgs: []string{"-f", "{TARGET}", "windows.netscan"}, TargetParam: "dump_path"},
		"vol_windows_malfind":   {Name: "vol_windows_malfind", Description: "Finds hidden/injected code (malware).", Binary: "vol", FixedArgs: []string{"-f", "{TARGET}", "windows.malfind"}, TargetParam: "dump_path"},
		"vol_windows_cmdline":   {Name: "vol_windows_cmdline", Description: "Extracts command line arguments of processes.", Binary: "vol", FixedArgs: []string{"-f", "{TARGET}", "windows.cmdline"}, TargetParam: "dump_path"},
		"vol_windows_dlllist":   {Name: "vol_windows_dlllist", Description: "Lists loaded DLLs for processes.", Binary: "vol", FixedArgs: []string{"-f", "{TARGET}", "windows.dlllist"}, TargetParam: "dump_path"},
		"vol_windows_filescan":  {Name: "vol_windows_filescan", Description: "Scans for file objects in memory.", Binary: "vol", FixedArgs: []string{"-f", "{TARGET}", "windows.filescan"}, TargetParam: "dump_path"},
		
		// ==========================================
		// SLEUTHKIT (DISK/FILE SYSTEM FORENSICS)
		// ==========================================
		"tsk_fls":    {Name: "tsk_fls", Description: "Lists files/directories in a disk image.", Binary: "fls", FixedArgs: []string{"-r", "{TARGET}"}, TargetParam: "image_path"},
		"tsk_ils":    {Name: "tsk_ils", Description: "Lists inode information.", Binary: "ils", FixedArgs: []string{"{TARGET}"}, TargetParam: "image_path"},
		"tsk_fsstat": {Name: "tsk_fsstat", Description: "Displays file system statistical info.", Binary: "fsstat", FixedArgs: []string{"{TARGET}"}, TargetParam: "image_path"},
		"tsk_mmls":   {Name: "tsk_mmls", Description: "Displays partition layout of a volume.", Binary: "mmls", FixedArgs: []string{"{TARGET}"}, TargetParam: "image_path"},
		
		// ==========================================
		// WINDOWS ARTIFACTS (REGISTRY, EVTX, PREFETCH)
		// ==========================================
		"parse_evtx":         {Name: "parse_evtx", Description: "Dumps Windows Event Logs (EVTX) to text.", Binary: "evtx_dump", FixedArgs: []string{"{TARGET}"}, TargetParam: "evtx_file"},
		"rip_sam":            {Name: "rip_sam", Description: "Parses SAM registry hive for users.", Binary: "rip.pl", FixedArgs: []string{"-r", "{TARGET}", "-f", "sam"}, TargetParam: "hive_file"},
		"rip_software":       {Name: "rip_software", Description: "Parses SOFTWARE registry hive.", Binary: "rip.pl", FixedArgs: []string{"-r", "{TARGET}", "-f", "software"}, TargetParam: "hive_file"},
		"rip_system":         {Name: "rip_system", Description: "Parses SYSTEM registry hive.", Binary: "rip.pl", FixedArgs: []string{"-r", "{TARGET}", "-f", "system"}, TargetParam: "hive_file"},
		"parse_amcache":      {Name: "parse_amcache", Description: "Parses Amcache.hve for program execution.", Binary: "amcacheparser", FixedArgs: []string{"-f", "{TARGET}", "--csv", "/tmp/"}, TargetParam: "amcache_file"},
		
		// ==========================================
		// TIMELINE & PLASO
		// ==========================================
		"plaso_log2timeline": {Name: "plaso_log2timeline", Description: "Extracts all events from disk into a database.", Binary: "log2timeline.py", FixedArgs: []string{"--quiet", "/tmp/timeline.plaso", "{TARGET}"}, TargetParam: "image_path"},
		"plaso_psort":        {Name: "plaso_psort", Description: "Filters Plaso timeline into readable text.", Binary: "psort.py", FixedArgs: []string{"-o", "dynamic", "{TARGET}"}, TargetParam: "plaso_file"},

		// ==========================================
		// NETWORK FORENSICS
		// ==========================================
		"pcap_tshark_dns":  {Name: "pcap_tshark_dns", Description: "Extracts DNS queries from a PCAP file.", Binary: "tshark", FixedArgs: []string{"-r", "{TARGET}", "-T", "fields", "-e", "dns.qry.name", "-Y", "dns.flags.response eq 0"}, TargetParam: "pcap_file"},
		"pcap_tshark_http": {Name: "pcap_tshark_http", Description: "Extracts HTTP requests from a PCAP.", Binary: "tshark", FixedArgs: []string{"-r", "{TARGET}", "-Y", "http.request"}, TargetParam: "pcap_file"},
		
		// ==========================================
		// MALWARE & STATIC ANALYSIS
		// ==========================================
		"analyze_strings": {Name: "analyze_strings", Description: "Extracts human-readable strings from malware.", Binary: "strings", FixedArgs: []string{"-a", "{TARGET}"}, TargetParam: "file_path"},
		"analyze_clamav":  {Name: "analyze_clamav", Description: "Scans a file with ClamAV antivirus.", Binary: "clamscan", FixedArgs: []string{"{TARGET}"}, TargetParam: "file_path"},
		"analyze_pescan":  {Name: "analyze_pescan", Description: "Scans Windows PE headers for anomalies.", Binary: "pescan", FixedArgs: []string{"{TARGET}"}, TargetParam: "file_path"},
		"analyze_exif":    {Name: "analyze_exif", Description: "Extracts metadata from files/images.", Binary: "exiftool", FixedArgs: []string{"{TARGET}"}, TargetParam: "file_path"},
	}
}