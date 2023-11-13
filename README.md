# AppFinger - Web Application Fingerprint Scanner

AppFinger is an open-source web application fingerprint scanner designed to identify and analyze web applications based on their unique characteristics.

## Usage

    Flags:
    APPFINGER:
    -l, -url-file string     File containing urls to scan
    -u, -url string[]        target url to scan (-u INPUT1 -u INPUT2)
    -t, -threads int         Number of concurrent threads (default 10) (default 10)
    -timeout int             Timeout in seconds (default 10) (default 10)
    -x, -proxy string        HTTP proxy to use for requests (e.g. http://127.0.0.1:7890)
    -s, -stdin               Read urls from stdin
    -d, -finger-home string  finger yaml directory home default is built-in
    
    HELP:
    -debug  debug
    
    OUTPUT:
    -o, -output string  file to write output to

## Example
    appfinger -u https://example.com

## How it Works

AppFinger scans web applications by analyzing their unique fingerprints, providing valuable insights into the technologies used.

## Contributing
Feel free to contribute to AppFinger by opening issues or submitting pull requests on GitHub.

## License
AppFinger is licensed under the MIT License. See the LICENSE file for details.

