# PyZeekCut

### Wrapper fo use zeek-cut within Python 3
#### Executes: cat logfile | zeek-cut ...

## Usage:

### zeeklog = ZeekCut(ZEEK_LOGFILE, columns = ['COLUMN': 'VALUE', ,..], options = ['ARGUMENT'],...)
####
### zeeklog.data => List of dictionaries containing the columns
####
### zeeklog.gentsv() => line-by-line generator for tab stop separation of colums
####
### zeeklog.gentsv() => line-by-line generator for CSV format
####
### zeeklog.json() => returns .data as a string in JSON format
####
### zeeklog.convert() => try to convert to values to int, float or IPv4/6Address
