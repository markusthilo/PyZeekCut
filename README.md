# PyZeekCut

Wrapper fo use zeek-cut within Python 3
This is executed: cat logfile | zeek-cut [<options>] <columns>

## Usage:
How to use:
zeeklog = ZeekCut(
	logfile, ### logfile can be a string or a list of filehandlers or strings
	columns = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
	options = '-d'
)
for line in zeeklog.gentsv:
	print(line)
for line in zeeklog.gentsv:
	print(line)
print(zeeklog.json)
print(zeeklog.data) - .data is a list of dictionaries, one element is e.g.: 'id.orig_h': '192.168.1.1'
