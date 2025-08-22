Script Creator: Devin Patel
Last Updated: 20250709

Description:
  Fetches CVE information from NVD using the nvdlib python module.
  Information is output in a CSV file using the same headers as OWASP Dependency Check.
  This script requires a connection to the internet.

NOTE:
  Due to rate limiting restrictions by NVD, a request will take 6 seconds with no API key.
  Requests with an API key have the ability to define a delay argument.
  The delay argument must be a integer/float greater than or equal to 0.6 (seconds).

Execution:
    Ensure nvdlib and all its dependencies are installed:
        $ pip install -r requirements.txt
          -or-
        $ pip install nvdlib requests
    Then:
        $ python3 fetch-nvd-cve.py --help

Usage:
  -h, --help           show this help message and exit
  --cve CVE [CVE ...]  A list of CVE IDs to fetch. These will be searched in addition to a --file input.
                           Example: --cve CVE-2022-24810 CVE-2022-24809
  --file FILE          A file of CVE IDs separated by newlines.
  --out OUT            Output file name. Will output to current directory by default.
  --api API            (optional) Set an NVD api key to speed up CVE searches. Without it, each CVE search will take 6 seconds.
  --delay DELAY        (optional) Manually set the delay between CVE searches in seconds. Only usable if an NVD api key is passed.

Dependencies:
  nvdlib
  requests
