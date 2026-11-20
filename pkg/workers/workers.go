package workers

import (
	"encoding/json"
	"fmt"

	"github.com/mr-rizwan-syed/argus/pkg/types"
	"github.com/mr-rizwan-syed/argus/pkg/utils"
)

// ProcessResults reads from resultInput and writes formatted lines to outputChannel.
// Runs until resultInput is closed. Intended to be called from multiple goroutines.
func ProcessResults(resultInput <-chan types.Result, outputChannel chan<- string, args types.ScrapeArgs) {
	for result := range resultInput {
		if result.Hit {
			if args.JsonOutput {
				b, err := json.Marshal(result.Certificate)
				if err != nil {
					continue
				}
				outputChannel <- string(b)
			} else {
				for _, domain := range result.Certificate.Domains {
					if args.PrintWildcards {
						if utils.IsWildcard(domain) || utils.IsValidDomain(domain) {
							outputChannel <- domain
							continue
						}
					}
					if utils.IsValidDomain(domain) && !utils.IsWildcard(domain) {
						outputChannel <- domain
					}
				}
			}
		} else if args.Debug {
			if result.Timeout {
				outputChannel <- fmt.Sprintf("Timed Out. No SSL certificate found for %s", result.IP)
			}
			if result.Error != nil {
				outputChannel <- fmt.Sprintf("Failed to get SSL certificate from %s: %v", result.IP, result.Error)
			}
		}
	}
}
