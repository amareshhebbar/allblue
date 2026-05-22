package registry

type SiftTool struct {
	Name        string
	Description string
	Binary      string
	FixedArgs   []string
	TargetParam string
}

func GetToolArsenal() map[string]SiftTool {
	return map[string]SiftTool{

		// ──────────────────────────────────────────────────────
		// VOLATILITY 3 — Memory Forensics
		// ──────────────────────────────────────────────────────
		"vol_windows_info": {
			Binary:      "vol",
			Description: "Extracts OS version, build, and kernel base address from memory.",
			FixedArgs:   []string{"-f", "{TARGET}", "windows.info"},
			TargetParam: "dump_path",
		},
		"vol_windows_pslist": {
			Binary:      "vol",
			Description: "Scans memory pool tags for processes — finds hidden processes that pslist misses.",
			FixedArgs:   []string{"-f", "{TARGET}", "windows.psscan"},
			TargetParam: "dump_path",
		},
		"vol_windows_pstree": {
			Binary:      "vol",
			FixedArgs:   []string{"-f", "{TARGET}", "windows.psscan"}, 
			TargetParam: "dump_path",
		},
		"vol_windows_netscan": {
			Binary:      "vol",
			Description: "Lists active and recently closed network connections. Find C2 IPs here.",
			FixedArgs:   []string{"-f", "{TARGET}", "windows.netscan"},
			TargetParam: "dump_path",
		},
		"vol_windows_malfind": {
			Binary:      "vol",
			Description: "Detects code injection, process hollowing, and shellcode (MZ headers in RWX memory).",
			FixedArgs:   []string{"-f", "{TARGET}", "windows.malfind"},
			TargetParam: "dump_path",
		},
		"vol_windows_cmdline": {
			Binary:      "vol",
			Description: "Extracts full command line of every process. Reveals attacker tools and encoded payloads.",
			FixedArgs:   []string{"-f", "{TARGET}", "windows.cmdline"},
			TargetParam: "dump_path",
		},
		"vol_windows_dlllist": {
			Binary:      "vol",
			Description: "Lists all loaded DLLs. Flags unsigned DLLs from temp/appdata directories.",
			FixedArgs:   []string{"-f", "{TARGET}", "windows.dlllist"},
			TargetParam: "dump_path",
		},
		"vol_windows_filescan": {
			Binary:      "vol",
			Description: "Scans memory for FILE_OBJECT references — finds files open at time of capture.",
			FixedArgs:   []string{"-f", "{TARGET}", "windows.filescan"},
			TargetParam: "dump_path",
		},
		"vol_windows_handles": {
			Binary:      "vol",
			Description: "Lists open handles (files, registry keys, mutants) per process.",
			FixedArgs:   []string{"-f", "{TARGET}", "windows.handles"},
			TargetParam: "dump_path",
		},
		"vol_windows_svcscan": {
			Binary:      "vol",
			Description: "Scans for Windows services — finds rogue/persistence services.",
			FixedArgs:   []string{"-f", "{TARGET}", "windows.svcscan"},
			TargetParam: "dump_path",
		},

		// ──────────────────────────────────────────────────────
		// SLEUTH KIT — Disk / Filesystem Forensics
		// ──────────────────────────────────────────────────────
		"tsk_fls": {
			Binary:      "fls",
			Description: "Lists all files and directories in a disk image (recursive).",
			FixedArgs:   []string{"-r", "{TARGET}"},
			TargetParam: "image_path",
		},
		"tsk_fls_deleted": {
			Binary:      "fls",
			Description: "Lists ONLY deleted files — used when attacker has cleaned up executables.",
			FixedArgs:   []string{"-r", "-d", "{TARGET}"},
			TargetParam: "image_path",
		},
		"tsk_ils": {
			Binary:      "ils",
			Description: "Lists inode information — finds deleted files with recoverable inodes.",
			FixedArgs:   []string{"{TARGET}"},
			TargetParam: "image_path",
		},
		"tsk_fsstat": {
			Binary:      "fsstat",
			Description: "Displays filesystem metadata (type, cluster size, MFT offset).",
			FixedArgs:   []string{"{TARGET}"},
			TargetParam: "image_path",
		},
		"tsk_mmls": {
			Binary:      "mmls",
			Description: "Shows partition layout with sector offsets.",
			FixedArgs:   []string{"{TARGET}"},
			TargetParam: "image_path",
		},

		// ──────────────────────────────────────────────────────
		// WINDOWS ARTIFACTS — Registry, Event Logs, Prefetch
		// ──────────────────────────────────────────────────────
		"rip_sam": {
			Binary:      "rip.pl",
			Description: "Parses SAM hive — extracts local user accounts and last login times.",
			FixedArgs:   []string{"-r", "{TARGET}", "-f", "sam"},
			TargetParam: "hive_file",
		},
		"rip_software": {
			Binary:      "rip.pl",
			Description: "Parses SOFTWARE hive — installed programs, run keys, shimcache.",
			FixedArgs:   []string{"-r", "{TARGET}", "-f", "software"},
			TargetParam: "hive_file",
		},
		"rip_system": {
			Binary:      "rip.pl",
			Description: "Parses SYSTEM hive — services, network config, timezone, USB history.",
			FixedArgs:   []string{"-r", "{TARGET}", "-f", "system"},
			TargetParam: "hive_file",
		},
		"rip_ntuser": {
			Binary:      "rip.pl",
			Description: "Parses NTUSER.DAT — user activity, recent docs, typed URLs, run MRU.",
			FixedArgs:   []string{"-r", "{TARGET}", "-f", "ntuser"},
			TargetParam: "hive_file",
		},
		"parse_evtx": {
			Binary:      "evtx_dump",
			Description: "Dumps Windows Event Logs to JSON — find 4624/4625 logins, 7045 service installs.",
			FixedArgs:   []string{"{TARGET}"},
			TargetParam: "evtx_file",
		},
		"parse_amcache": {
			Binary:      "amcacheparser",
			Description: "Parses Amcache.hve — execution evidence for files that no longer exist on disk.",
			FixedArgs:   []string{"-f", "{TARGET}", "--csv", "/tmp/"},
			TargetParam: "amcache_file",
		},

		// ──────────────────────────────────────────────────────
		// TIMELINE — Plaso / log2timeline
		// Note: log2timeline arg order is: storage_file SOURCE
		// ──────────────────────────────────────────────────────
		"plaso_log2timeline": {
			Binary:      "log2timeline.py",
			Description: "Builds a super-timeline from all artefact sources in the disk image.",
			FixedArgs:   []string{"--storage-file", "/tmp/timeline.plaso", "{TARGET}"},
			TargetParam: "image_path",
		},
		"plaso_psort": {
			Binary:      "psort.py",
			Description: "Filters and exports Plaso storage to human-readable CSV/JSON.",
			FixedArgs:   []string{"-o", "dynamic", "--storage-file", "{TARGET}"},
			TargetParam: "plaso_file",
		},

		// ──────────────────────────────────────────────────────
		// NETWORK FORENSICS — tshark / pcap analysis
		// ──────────────────────────────────────────────────────
		"pcap_tshark_dns": {
			Binary:      "tshark",
			Description: "Extracts DNS query names from a PCAP — reveals C2 domain beaconing.",
			FixedArgs:   []string{"-r", "{TARGET}", "-T", "fields", "-e", "dns.qry.name", "-Y", "dns.flags.response eq 0"},
			TargetParam: "pcap_file",
		},
		"pcap_tshark_http": {
			Binary:      "tshark",
			Description: "Extracts HTTP requests (method, host, URI) from a PCAP.",
			FixedArgs:   []string{"-r", "{TARGET}", "-Y", "http.request", "-T", "fields", "-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri"},
			TargetParam: "pcap_file",
		},
		"pcap_tshark_streams": {
			Binary:      "tshark",
			Description: "Lists all TCP conversations with byte counts — find large exfiltration streams.",
			FixedArgs:   []string{"-r", "{TARGET}", "-q", "-z", "conv,tcp"},
			TargetParam: "pcap_file",
		},

		// ──────────────────────────────────────────────────────
		// MALWARE & STATIC ANALYSIS
		// ──────────────────────────────────────────────────────
		"analyze_strings": {
			Binary:      "strings",
			Description: "Extracts printable strings from a binary — find URLs, IPs, registry keys, and C2 config.",
			FixedArgs:   []string{"-a", "-n", "6", "{TARGET}"},
			TargetParam: "file_path",
		},
		"analyze_clamav": {
			Binary:      "clamscan",
			Description: "Scans a file or directory with ClamAV signatures.",
			FixedArgs:   []string{"--no-summary", "{TARGET}"},
			TargetParam: "file_path",
		},
		"analyze_exif": {
			Binary:      "exiftool",
			Description: "Extracts metadata from files — reveals author, GPS, creation timestamps.",
			FixedArgs:   []string{"-a", "-u", "{TARGET}"},
			TargetParam: "file_path",
		},
		"analyze_file_type": {
			Binary:      "file",
			Description: "Identifies true file type by magic bytes — catches executables renamed as .txt.",
			FixedArgs:   []string{"-b", "{TARGET}"},
			TargetParam: "file_path",
		},
	}
}