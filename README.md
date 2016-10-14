# ThreatParse
Parses Fidelis Endpoint threatscan xml result files to produce CSV reports.

Currently Parses:
* Registry Hits
* EventLog Hits
* File Hits
* Process Hits
* URL Hits
* Module Errors
* Truncated File Hits

Requires: Python 3+

Usage: (-h when running)

usage: threatparse.py [-h] [-e EXCLUDE_THREATS [EXCLUDE_THREATS ...]] folder

positional arguments:
  folder                File path containing the job results.

optional arguments:
  -h, --help            show this help message and exit
  -e EXCLUDE_THREATS [EXCLUDE_THREATS ...], --exclude_threats EXCLUDE_THREATS [EXCLUDE_THREATS ...]
                        Exclude threats by ID. Ex: -e 24 576 255
