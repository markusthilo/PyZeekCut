#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.4-20201029'
__license__ = 'GPL-3'
__help__ = '''
Wrapper for zeek-cut
This is executed: cat <logfiles> | zeek-cut [<options>] <columns>
Usage / example:
zeekcut = ZeekCut()
zeeklog = zeekcut.run(
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

from os import environ, path, access, X_OK
from subprocess import Popen, PIPE
from ipaddress import ip_address
from json import dumps

class ZeekCut:
	'Python wrapper for zeek-cut'

	PATHS = [	# possible paths to look for zeek-cut executable
		'/usr/local/zeek/bin',
		'/opt/zeek/bin',
		'/usr/local/bin',
		'/usr/bin'
	]
	ZEEKCUT = 'zeek-cut'	# define command for zeek-cut
	CAT = 'cat'	# define command for cat

	def __init__(self, zeekcut=None, cat=None):
		'Create Object for zeek-cut'
		if zeekcut == None:
			for directory in environ['PATH'].split(':') + self.PATHS:
				self.zeekcut = path.join(directory, self.ZEEKCUT)
				if path.isfile(self.zeekcut) and access(self.zeekcut, X_OK):
					break
		else:
			self.zeekcut = zeekcut
		if cat == None:
			self.cat = self.CAT
		else:
			self.cat = cat
		
	def run(self,
		logfiles,
		columns = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
		options = None
	):
		'Execute cat logfile | zeek-cut [<options>] <columns>'
		cat_cmd = [self.cat]	# assemble shell command for cat
		cat_cmd.extend(self.__convert2list__(logfiles))
		zeek_cmd = [self.zeekcut]
		if options != None:	# assemble shell command for zeek-cut
			zeek_cmd.extend(self.__convert2list__(options))
		zeek_cmd.extend(columns)
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
							break
						except ValueError:
							pass

	def json(self):
		'Give data in JSON format'
		return dumps(self.data)

	def __convert2list__(self, arg):
		'Convert argument to a list'
		if isinstance(arg, list):
			try:
				return [ f.name for f in arg ]
			except AttributeError:
				return arg
		if isinstance(arg, str):
			return [arg]
		return list(arg)
