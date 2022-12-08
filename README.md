# vturl

## virustotal.com api url analysis script

vturl.py takes a single url or list of urls (or IPs), runs them against VirusTotal's API and displays a verdict based on various criteria. It also dumps the entire JSON response to file for later analysis. 

## Usage:  

```
vturl.py -s example.com (single url)
vturl.py -f file.txt (input file, one url per line)
vturl.py -d file.txt (dry run)
```

- virus total api key should be saved in env var 'VT_API_KEY'
- http proxy, if needed, should be saved in env var 'VT_HTTP_PROXY'
- output is written to console and logfile
- full json data for each url is written to urls directory (url id as filename)

## Todo:  

- parse and display additional data, if potentialy malicious (categories, etc)
- clean up output and logging format
- add option to re-scan scanned urls
- add option to re-scan all urls
- filtering (subnets, domains, etc)
