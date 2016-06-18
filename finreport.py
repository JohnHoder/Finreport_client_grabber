#!/usr/bin/env
# -*- coding: utf-8 -*-
import re
import cookielib
import urllib
import urllib2
import logging
import sys

try:
	import requests
	from bs4 import BeautifulSoup
	from prettytable import PrettyTable

except ImportError:
		print "\nPlease make sure you have BeautifulSoup and requests modules installed!\n"
		exit()

DEBUG = False

if DEBUG == True:
	try:
		import http.client as http_client
	except ImportError:
		# Python 2
		import httplib as http_client

	http_client.HTTPConnection.debuglevel = 1

	# You must initialize logging, otherwise you'll not see debug output.
	logging.basicConfig()
	logging.getLogger().setLevel(logging.DEBUG)
	requests_log = logging.getLogger("requests.packages.urllib3")
	requests_log.setLevel(logging.DEBUG)
	requests_log.propagate = True

class FinreportAutomatic(object):

	#Save to TXT=1 HTML=2
	def __init__(self, username, password, saveTo):
		super(FinreportAutomatic, self).__init__()
		self.username = username
		self.password = password
		self.saveTo = saveTo

		self.session = requests.Session()

	def getTextOnly(self, soupedHtml):
		# kill all script and style elements
		for script in soupedHtml(["script", "style"]):
			script.extract()    # rip it out
		# get text
		text = soupedHtml.get_text(separator=' ')
		# break into lines and remove leading and trailing space on each
		lines = (line.strip() for line in text.splitlines())
		# break multi-headlines into a line each
		chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
		# drop blank lines
		text = '\n'.join(chunk for chunk in chunks if chunk)

		return (text)


	def login(self):
		headers={
				"Host" : "www.finreport.cz",
				"User-Agent" : "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0",
				"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language" : "en-US,en;q=0.5",
				"Accept-Encoding" : "gzip, deflate, br",
				"Referer" : "https://www.finreport.cz/",
				"Connection" : "close",
				"Content-Type" : "application/x-www-form-urlencoded",
				}

		params = {"action" : "login",
					"pathback" : "https://www.finreport.cz/finreport/"}

		url_login = 'https://www.finreport.cz/index.php'

		payload= {'username' : self.username, 'password' : self.password}

		#with requests.Session() as session:

		res = self.session.post(url_login, params=params, data=payload, headers=headers, allow_redirects=False)
		print "######################################################"
		print "######################################################"

		redir_loc = res.headers['Location']
		print res.status_code, res.reason, " => ", redir_loc
		print "PHPSESSID:", res.cookies['PHPSESSID']

		main = self.session.get(redir_loc, allow_redirects=True)
		#print request.headers
		#print main.text

		print "######################################################"
		print "######################################################"

	url_klienti = "https://www.finreport.cz/finreport/control_klienti.php"

	headers2 = {
				"Host" : "www.finreport.cz",
				"User-Agent" : "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0",
				"Accept" : "*/*",
				"Accept-Language" : "en-US,en;q=0.5",
				"Accept-Encoding" : "gzip, deflate, br",
				"X-Requested-With" : "XMLHttpRequest",
				"Referer" : "https://www.finreport.cz/finreport/index.php?app=klienti",
				"Content-Type" : "application/x-www-form-urlencoded; charset=UTF-8"
				}

	def getClients(self):

		payload2= {'action' : 'index'}

		klienti_idx = self.session.post(self.url_klienti, data=payload2, headers=self.headers2, allow_redirects=True)
		klienti_idx.encoding = 'utf-8'

		soup = BeautifulSoup(klienti_idx.text, "lxml")
		soup.prettify()
		div = soup.find('div', attrs={'class': 'output_content'})
		#print div
		lel_id = div.find_all('div', attrs={'class': 'flybox_text', 'id' : re.compile("flybox_text_klienti-fly-"), 'ref' : '0', 'rel' : '0', 'style' : 'display: none;'})
		lel_name = div.find_all('tr', attrs={'class' : 'finder-item core-table-row', 'id' : re.compile("core-table-row-klienti:index-")})

		clients = {}

		i = 0
		for x in lel_id:
			#ids.append(lel_id[i]['id'][24:])
			#names.append(lel_name[i]['data-finder-index'])
			clients[lel_id[i]['id'][24:]] = lel_name[i]['data-finder-index']
			print "Klient", lel_id[i]['id'][24:], "=>", lel_name[i]['data-finder-index']
			i = i+1

		ids = clients.keys()
		names = clients.values()

		print "\nNalezeno %s klientu." % (i)
		return clients


	def getInfoAndSave(self, clients):
		charset = "<meta charset=\"UTF-8\">"

		ext = ''
		if self.saveTo == True:
			ext = '.html'
		else:
			ext = '.txt'
		out = file('klienti' + ext,'w')

		if self.saveTo == True:
			out.write(charset)

		cnt = 0
		ids = clients.keys()
		names = clients.values()

		for klient in ids:
			payload3= {'action' : 'open', 'klientid' : klient}

			klienti_data = self.session.post(self.url_klienti, data=payload3, headers=self.headers2, allow_redirects=True)
			klienti_data.encoding = 'utf-8'
			htmlText = klienti_data.text
			soup_data = BeautifulSoup(htmlText, "lxml")

			cut = soup_data.find('div', attrs={'style' : 'margin-left: 180px'})
			#print cut.prettify()

			textOnly = self.getTextOnly(cut)
			#Strip first line - "Osobni info"
			textOnly = '\n'.join(textOnly.split('\n')[1:]).encode('utf-8')
			print textOnly

			out.write(names[cnt].encode('utf-8') + '\n')

			if self.saveTo == True:
				out.write(cut.encode('utf-8'))
			else:
				out.write(textOnly)
				out.write("\n\n\n")

			#MAYBE A TABLE LAYOUT IN THE FUTURE?

			#table = PrettyTable(["Type", "Departure", "Arrival", "Seats", "Price"])
			#table.align["Seats"] = "r"
			#table.align["Price"] = "r"
			#print table
			
			cnt = cnt + 1

		out.close()


if __name__ == "__main__":
	username = ""
	password = ""

	sa = FinreportAutomatic(username, password, False)
	sa.login()
	sa.getInfoAndSave(sa.getClients())

