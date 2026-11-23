package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mr-rizwan-syed/argus/pkg/scrape"
	"github.com/mr-rizwan-syed/argus/pkg/types"
)

func main() {
	args := types.ScrapeArgs{}
	scrapeUsage := "-i <IPs/CIDRs or File> "

	flag.IntVar(&args.Concurrency, "c", 0, "Goroutine concurrency (0 = auto-detect from CPU/RAM/FD limits)")
	flag.StringVar(&args.PortList, "p", "443", "TLS ports to check for certificates")
	flag.IntVar(&args.Timeout, "t", 4, "Timeout for TLS handshake")
	flag.StringVar(&args.Input, "i", "NONE", "Either IPs & CIDRs separated by commas, or a file with IPs/CIDRs on each line")
	flag.BoolVar(&args.Debug, "debug", false, "Add this flag if you want to see failures/timeouts")
	flag.BoolVar(&args.Help, "h", false, "Show the program usage message")
	flag.BoolVar(&args.JsonOutput, "j", false, "print cert data as jsonl")
	flag.BoolVar(&args.PrintWildcards, "wc", false, "print wildcards to stdout")
	flag.StringVar(&args.Order, "order", "sequential", "Probe order: sequential (input order) or random (spreads load so no network sees a burst)")
	flag.Uint64Var(&args.Seed, "seed", 0, "Random order: seed (0 = pick one; it is printed and kept in the checkpoint)")
	flag.IntVar(&args.Rate, "rate", 0, "Most probes started per second (0 = no cap)")
	flag.IntVar(&args.SynRetries, "syncnt", 0, "Give up a connect after this many SYN retransmits (0 = kernel default, about 2 minutes; Linux)")
	flag.BoolVar(&args.FastClose, "fast-close", false, "Close sockets with a reset instead of FIN + TIME_WAIT (Linux)")
	flag.BoolVar(&args.Resume, "resume", false, "Resume from checkpoint (<input>.argchk) if one exists")
	//flag.BoolVar(&args.Help, "stats", false, "Print stats at the end")

	flag.Parse()

	if args.Help {
		fmt.Println(scrapeUsage)
		flag.PrintDefaults()
		return
	}

	// Read stdin into a temp file so large feeds don't buffer in memory.
	// Temp files are ephemeral so checkpointing is disabled for stdin inputs.
	if args.Input == "NONE" {
		tmp, err := os.CreateTemp("", "argus-stdin-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating temp file: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove(tmp.Name())

		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				fmt.Fprintln(tmp, line)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
		tmp.Close()
		args.Input = tmp.Name()
		args.NoCheckpoint = true
	}

	if args.Order != "sequential" && args.Order != "random" {
		fmt.Fprintf(os.Stderr, "[argus] input error: -order must be sequential or random (got %q)\n", args.Order)
		os.Exit(2)
	}
	args.Ports = strings.Split(args.PortList, ",")

	scrape.RunScrape(args)
}
