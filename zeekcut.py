#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.3-20200402'
__license__ = 'GPL-3'
__help__ = '''
Wrapper for zeek-cut
This is executed: cat <logfiles> | zeek-cut [<options>] <columns>
Usage / example:
zeeklog = ZeekCut(
	logfiles,
	columns = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
	options = '-d'
)
for line in zeeklog.gentsv:
	print(line)
for line in zeeklog.gentsv:
	print(line)
print(zeeklog.json)
print(zeeklog.data)
'''

from subprocess import Popen, PIPE
from ipaddress import ip_address
from json import dumps

class ZeekCut:
	'Python wrapper for zeek-cut'

	ZEEKCUT = '/usr/local/zeek/bin/zeek-cut'	# set path to zeek-cut here!!!

	def __init__(self,
		logfiles,
		columns = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
		options = None
	):
		'''
			Create Object for zeek-cut:
			cat logfile | zeek-cut [<options>] <columns>
		'''
		self.logfiles = []	# create a list of filenames as strings
		if isinstance(logfiles, str):
			self.logfiles = [logfiles]
		else:
			for logfile in logfiles:
				if isinstance(logfile, str):
					self.logfiles.append(logfile)
				else:
					self.logfiles.append(logfile.name)
		cat_cmd = ['cat']	# assemble shell command for cat
		cat_cmd.extend(self.logfiles)
		zeek_cmd = [self.ZEEKCUT]	# assemble shell command for zeek-cut
		if options != None:
			zeek_cmd.extend(self.__convert2list__(options))
		zeek_cmd.extend(self.__convert2list__(columns))
		cat = Popen(cat_cmd, stdout=PIPE)	# generate cat
		zeekcut = Popen(zeek_cmd, stdin=cat.stdout, stdout=PIPE)	# generate zeek-cut
		lines = zeekcut.communicate()[0].decode().rstrip('\n').split('\n')	# read lines from stdout
		if options != None and ( '-c' in options or '-C' in options ):
			self.data = [{ tab: tab for tab in columns }]
		else:
			self.data = []
		self.data += [{colname: colvalue for colname, colvalue in zip(columns, line.split('\t'))} for line in lines if line[0] != '#']
		self.columns = columns
		self.options = options

	def gentsv(self):
		'Generator for TSV format'
		for line in self.data:
			yield '\t'.join(map(lambda tab: str(line[tab]), self.columns))

	def gencsv(self):
		'Generator for CSV format'
		for line in self.data:
			yield '"' + '","'.join(map(lambda tab: str(line[tab]), self.columns)) + '"'

	def convert(self, force=dict()): 
		'Try to convert values of tabs to int, float or IP addresses'
		for line in self.data:
			for tab in line:
				if tab in force:
					if force[tab] in (int, float) and line[tab] == '-':
						line[tab] = force[tab](0)
					else:
						line[tab] = force[tab](line[tab])
				else:
					for form in int, float, ip_address:
						try:
							line[tab] = form(line[tab])
						except ValueError:
							pass

	def json(self):
		'Give data in JSON format'
		return dumps(self.data)

	def __convert2list__(self, arg):
		'Convert argument to a list'
		if isinstance(arg, list):
			return arg
		if isinstance(arg, str):
			return [arg]
		return list(arg)
