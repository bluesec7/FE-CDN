#!/usr/bin/python2

"""
Feel free to re-distribute, modifying, and use this project.
Unleash the power of Open Source! :'

Have any question?
Just visit and leave a comment to my blog.
Don't forget to visit my blog :*
"""


from __future__ import print_function
from requests import get
from urlparse import urlparse
from dns.resolver import query, NoAnswer, NXDOMAIN, NoNameservers, Timeout
import sys


__author__ = 'bluesec7'
__site__ = 'https://kagurasuki.blogspot.com'
__contact__ = 'https://facebook.com/silent.v0id'


def A(domain):
	'this func sometime helpful :)'
	print('Checking Multiple IP...')
	try:
		asw = query(domain)
	except NXDOMAIN:
		raise NXDOMAIN("Are you sure %r exist?"%domain)
	except NoNameservers:
		raise NoNameservers('No nameserver found for %r'%domain)
	except NoAnswer:
		raise NoAnswer('No IP for %s!'%domain)
	print('Found IP: %s'%[str(a.address) for a in asw ])
	print('Checking CNAME...')
	try:
		asw = query(domain, 'cname')
		domains =  [ a.to_text() for a in asw ]
		print('Found that %s have another domains: %s'%(domain,','.join(domains)))
	except Exception as e:
		print(e)
	print()


class FrontEndCDN:
	'Attempt to demonstrate FrontEnd CDN.'
	timeout = 5
	
	def verifURL(self, url):
		URL = urlparse(url)
		if not URL.scheme:
			print('Please provide the URL scheme for %s'%url)
			raise ValueError('No URL scheme given')
		return URL
	
	def retrieve(self, URL, dest):
		url = self.verifURL(URL)
		h = {'host':dest}
		print('Retrieving resource %s ...'%url.path)
		try:
			r = get(URL, headers=h, timeout=self.timeout)
		except Exception as e:
			print('Failed to retrieve')
			raise e
		else:
			headers = r.headers
			rsc = r.content
			print('done %d bytes received'%len(rsc))
			print(r.status_code, r.reason)
			print('from %s'%url.netloc)
			# check headers
			if 'via' in headers:
				print('Via: %s'%headers['via'])
			if 'x-cache' in headers:
				print('X-Cache: %s'%headers['x-cache'])
				
			if r.status_code != 200:
				raise Exception('Invalid response returned: %d %s'%(r.status_code, r.reason))
			print()
			return rsc
	
	def nqtest(self, (u1, u2), blocked):
		'Use 2 different allowed sites'
		url = self.verifURL(blocked)
		l1 = self.verifURL(u1)
		l2 = self.verifURL(u2)
		f1 = '%s://%s%s'%(l1.scheme, l1.netloc, url.path)
		f2 = '%s://%s%s'%(l2.scheme, l2.netloc, url.path)
		rsc = self.retrieve(f1, url.netloc)
		res = self.retrieve(f2, url.netloc)
		print('Comparing...')
		if res == rsc:
			print('Wow FE was succesful :)\nOmedeto \\`o`/')
		else:
			print('Something wrong...')
		out = open('fe-cdn.allowed.rsc.txt', 'w')
		out.write(rsc)
		out.close()
		out = open('fe-cdn.allowed.res.txt', 'w')
		out.write(res)
		out.close()
		print('Output was saved')
		
	def test(self, unblocked, blocked):
		allowed = self.verifURL(unblocked)
		url = self.verifURL(blocked)
		
		rsc = self.retrieve(blocked, url.netloc)
		print('Attempting for domain fronting...')
		final = '%s://%s%s'%(allowed.scheme, allowed.netloc, url.path)
		res = self.retrieve(final, url.netloc)
		if res == rsc:
			print('Wow FE was succesful :)\nOmedeto \\`o`/')
		else:
			print('Something wrong...')
		out = open('fe-cdn.blocked.rsc.txt', 'w')
		out.write(rsc)
		out.close()
		out = open('fe-cdn.allowed.res.txt', 'w')
		out.write(res)
		out.close()
		print('Output was saved')


usage = 'Usage:\n\t%s blocked-site-url (allowed-site-url)\n\tblocked-site-url may be https://blocked.example/ (blocked site url that you want to retrieve the content. Usually behind a CDN).\n\tallowed-site-url may be https://allowed.example or https://allowed1.example https://allowed2.example'%sys.argv[0]

if __name__=='__main__':
	allowed2 = None
	if len(sys.argv) >= 3:
		blocked = sys.argv[1]
		allowed1 = sys.argv[2]
	if len(sys.argv) >= 4:
		allowed2 = sys.argv[3]
	elif len(sys.argv) < 3:
		print(usage)
		exit(1)
	fe = FrontEndCDN()
	if not allowed2:
		fe.test(allowed1, blocked)
	else:
		fe.nqtest((allowed1, allowed2), blocked)




