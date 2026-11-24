# Sample rules for `argus monitor`

Run any of them live (matches print as they happen, one line each; Ctrl+C stops it):

```sh
argus monitor -rules examples/rules.json -stdout 2>monitor.log | jq --unbuffered -r '"\(.kind)\t\(.score)\t\(.domain)"'
```

The matches are JSON lines on stdout and the monitor's own log goes to `monitor.log`. Without `jq`, drop the pipe to see the raw JSON.

| File | What it watches | Expect |
|---|---|---|
| [`rules.json`](rules.json) | The brand words `paypal`, `microsoft`, `amazon`, `netflix` inside any domain | Hits within seconds. Many are the brands' own infrastructure; add `-min-score 70` for the more suspicious ones |
| [`rules-domain.json`](rules-domain.json) | New hosts under `amazonaws.com` (very busy), and `microsoft.com` with its look-alikes | `subdomain` hits within seconds; real look-alikes such as `microsoftporkbun.ph` or `help-rnicrosoft.com` now and then |
| [`rules-organization.json`](rules-organization.json) | Certificates whose subject organization is Google or Microsoft | Microsoft within a minute; Google every few minutes |
| [`rules-template.json`](rules-template.json) | A template with every field, for one organization (`acme.com` does not exist in the logs: replace it with your own) | Nothing, until you put your own names in |

## The fields of a rule

One rule is one organization. Every field is optional but a rule needs at least one of `apexes`, `keywords`, `orgs`; **leave a field out rather than giving it an empty list or an empty string** (`"apexes": [""]` makes the monitor refuse the whole file).

| Field | Meaning | Limits |
|---|---|---|
| `id` | Your name for the rule, returned in every match | 1 to 64 characters: letters, digits, `. _ : -` |
| `name` | A label for people | up to 100 characters |
| `apexes` | Your domains. New certificates for them and everything under them are reported as `subdomain`, and imitations of their names as `lookalike` | up to 5 |
| `keywords` | A brand word looked for inside other people's domains (phishing, brand abuse) | up to 5; 4 to 40 characters; letters, digits and inner hyphens; very common words such as `bank` or `cloud` are refused |
| `orgs` | An organization name looked for in the certificate's subject (whole words, case and endings such as Inc or Ltd ignored) | up to 5; 3 to 100 characters |
| `known` | Hosts or domains that are your own: never reported, and nothing under them either | up to 50 |

Useful flags: `-min-score 70` (drop weak hits), `-daily-cap 500` (most hits per rule per day), `-out matches.jsonl` (write to a file), `-h` (all of them).
