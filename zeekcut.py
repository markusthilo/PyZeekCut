#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.1-20200306'
__license__ = 'GPL-3'
__help__ = '''
Wrapper for zeek-cut
This is executed: cat logfile | zeek-cut [<options>] <columns>
Usage:
zeeklog = ZeekCut(
	logfile,
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
from json import dumps

class ZeekCut:
	'Python wrapper for zeek-cut'

	ZEEKCUT = '/usr/local/zeek/bin/zeek-cut'

	def __init__(self,
		logfile,
		columns = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
		options = None
	):
		'''
			Create Object for zeek-cut:
			cat logfile | zeek-cut [<options>] <columns>
			Warning: -c does not work!
			logfile can be a string or a file handler
		'''
		if isinstance(logfile, str):
			self.logfile = logfile
		else:
			self.logfile = logfile.name
		cmd = [self.ZEEKCUT]	# assemble shell command for zeek-cut
		if options != None:
			cmd.extend(self.__convert2list__(options))
		cmd.extend(self.__convert2list__(columns))
		cat = Popen(['cat', self.logfile], stdout=PIPE)	# generate cat
		zeekcut = Popen(cmd, stdin=cat.stdout, stdout=PIPE)	# generate zeek-cut
		lines = zeekcut.communicate()[0].decode().rstrip('\n').split('\n')	# read lines from stdout
		self.data = [{colname: colvalue for colname, colvalue in zip(cmd[-1*len(lines[0].split('\t')):], line.split('\t'))} for line in lines]

	def __convert2list__(self, arg):
		'Convert argument to a list'
		if isinstance(arg, str):
			return [arg]
		return list(arg)

	def gentsv(self):
		'Generator for TSV format'
		for line in self.data:
			yield ''.join(map(lambda tab: f'{line[tab]}\t', line))[:-1]

	def gencsv(self):
		'Generator for CSV format'
		for line in self.data:
			yield ''.join(map(lambda tab: f'"{line[tab]}",', line))[:-1]

	def json(self):
		'Give data in JSON format'
		return dumps(self.data)
