# trafd-parser

trafd-parser is a simply command-line utility to parse trafd datafile.

## Usage

```
perl trafd-parser.pl [-dhprs] <trafd.ifX> [ipaddr]

trafd.ifX - trafd binary data file with traffic
ipaddr    - count incoming traffic for that ipaddress

Options:
    -d    Show dump information: datetime and how many entries it have
    -r    Show detailed traffic records from dumps
    -h    Usage human form output calculation for specified ipaddr (see above)
    -p    Substitute numeric ip protocols by names in detailed traffic (/etc/protocols)
    -s    Substitute numeric services by names in detailed traffic (/etc/services)
```
