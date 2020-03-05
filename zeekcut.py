#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Wrapper for zeek-cut
# Markus Thilo
# markus.thilo@gmail.com
# GPL-3

from subprocess import Popen, PIPE
from json import dumps

class ZeekCut:
	'Python wrapper for zeek-cut'

	ZEEKCUT = '/opt/zeek/bin/zeek-cut'

	def __init__(self, logfile, columns, options=None):
		'''
			Create Object for zeek-cut:
			cat logfile | zeek-cut [<options>] <columns>
			Warning: -c does not work!
		'''
		self.logfile = logfile
		cmd = [self.ZEEKCUT]	# assemble shell command for zeek-cut
		if options != None:
			cmd.extend(self.__convert2list__(options))
		cmd.extend(self.__convert2list__(columns))
		cat = Popen(['cat', self.logfile], stdout=PIPE)	# generate cat
		zeekcut = Popen(cmd, stdin=cat.stdout, stdout=PIPE)	# generate zeek-cut
		lines = zeekcut.communicate()[0].rstrip('\n').split('\n')	# read lines from stdout
		self.data = [{colname: colvalue for colname, colvalue in zip(cmd[-1*len(lines[0].split('\t')):], line.split('\t'))} for line in lines]

	def __convert2list__(self, arg):
		'Convert argument to a list'
		if isinstance(arg, str):
			return [arg]
		return list(arg)

	def gentsv(self):
		'Generator for TSV format'
		for line in self.data:
			yield ''.join(map(lambda tab: f'(line(tab))\t'))[:-1]

	def gencsv(self):
		'Generator for CSV format'
		for line in self.data:
			yield ''.join(map(lambda tab: f'"(line(ttab))",'))[:-1]

	def json(self):
		'Give data in JSON format'
		return dumps(self.data)
