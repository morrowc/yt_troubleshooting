#!/usr/bin/python3
#
# Do some testing and data collection for YT problems.
# Follow standard troubleshooting guidelines for YT issues.
#
# For each test, provide v4 and v6 testing and collection.
#
import os
import re
import smtplib
import socket
from io import StringIO
import subprocess
import sys

from datetime import datetime
from email.mime.text import MIMEText
from optparse import OptionParser

_author_ = 'morrowc@ops-netman.net'
# The mapping_re won't find results if the entire string (and giant
# debug blob are included, trim to 80 chars after wget, before matching.
MAPPING_RE = re.compile(r'^.* => (\S+)\s*.*$')


def EmailResult(rcptto, content, mailfrom, mailhost):
  """Email results to the colletor.

  Args:
    rcptto: a string, email destination.
    content: a list, the content to send out to the collection point.
    mailfrom: a string, the from address for the mail.
    mailhost: a string, the destination to send mail through.
  """
  # Create a 'file' object type to Mime-ify.
  s = StringIO()
  s.write('\n'.join(content))

  # Mime-ify the message.
  msg = MIMEText(s.getvalue())
  s.close()

  msg['Subject'] = 'YT Diags (%s)' % datetime.strftime(datetime.utcnow(),
                                                       '%Y/%m/%d %H:%M')
  msg['From'] = mailfrom
  msg['To'] = rcptto

  # Attempt to send the message.
  try:
    s = smtplib.SMTP(mailhost)
    s.sendmail(mailfrom, rcptto, msg.as_string())
    s.quit()
  except smtplib.SMTPConnectError as e:
    print('Failed to send mail, connect error: %s' % e)
    sys.exit(1)
  except smtplib.SMTPDataError as e:
    print('Failed to send mail, data error: %s' % e)
    sys.exit(1)
  except smtplib.SMTPException as e:
    print('Failed to send mail, Exception: %s' % e)
    sys.exit(1)
  except smtplib.SMTPHeloError as e:
    print('Failed to send mail, Error in Helo: %s' % e)
    sys.exit(1)
  except socket.error as e:
    print('Failed to connect to the smtp/mailhost: %s' % mailhost)
    print( msg.as_string())
    sys.exit(1)
  

def Where(binary):
  """Where is the binary located? Find the first instance.

  Args:
    binary: a string, the name of the file to locate.

  Returns:
    a string, the path to the binary.
  """
  common_paths = ['/bin', '/usr/bin', '/usr/sbin/']
  for path in common_paths:
    if os.path.exists(os.path.join(path, binary)):
      return os.path.join(path, binary)


def Traceroute(dest, family='4'):
  """Traceroute to a destination.

  Args:
    dest: a string, the ip address/hostname to traceroute toward.
    family: a string, the address family to use in the tracroute.

  Return:
    a string, the traceroute results.
  """
  FAMILY = {'4': Where('traceroute'),
            '6': Where('traceroute6')}

  fd = subprocess.Popen('%s %s' % (FAMILY[family], dest), shell=True,
                        stdout=subprocess.PIPE).stdout

  return fd.read().decode()


def Resolver(name, family=socket.AF_INET):
  """Resolve a hostname in the right family.

  Args:
    name: a string, to lookup.
    family: a socket family.
  Results:
    a list of potential addresses for the name/family combination.
  """
  result = set([])
  try:
    for res in socket.getaddrinfo(name, 80, family):
      result.add(res[4][0])

  except socket.gaieror:
    pass

  return list(result)


def Wget(url, family='4', output='-', quiet='-q', grep=''):
  """Get a single URL, use wget cause it's simple.

  Args:
    url: a string, the URL to download.
    family: a string, the address family to lookup with.
    output: a string, where to send the wget output.
    grep: a string, the potential grep-like command to trim results with.

  Results:
    a string, the resulting content from the webpage.
  """
  wget = Where('wget')
  fd = subprocess.Popen('%s -%sO %s %s %s %s' %
                        (wget, family, output, quiet, url, grep),
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
  stdout, stderr = fd.communicate()
  return stdout.strip()


def V4Mappings():
  """Lookup and store information about the v4 mapping location.

  Return:
    a list of strings, to be added ot the overall result data.
  """
  result = []
  v4_redir = []
  # Find the redirector location(s).
  v4_redir = Resolver('redirector.c.youtube.com')
  print('v4 redirector addresses: %s' % ', '.join(v4_redir))
  result.append('v4 redirector.c.youtube.com: %s' % ', '.join(v4_redir))
  print('Tracerouting to all v4 redirector locations in turn.')
  result.append('Traceroute results to v4_redirector destinations.')
  for host in v4_redir:
    result.append(Traceroute(host))

  # Find the mapping location returned from the redirector.
  print('Asking for the v4 map location.')
  v4_mapping = Wget(
          'http://redirector.c.youtube.com/report_mapping', 
          '4').decode()[:80]
  result.append('v4 mapping:\n%s' % v4_mapping)
  m = MAPPING_RE.match(v4_mapping)
  if m:
    map_addr = m.group(1)
  else:
    print('No mapping address found for ipv4, stopping processing here.')
    return result

  print('v4 Mapping address: %s' % map_addr)
  if '-' in map_addr:
    result.append('Traceroute to GGC node:\n')
    result.append(Traceroute('%s.ba.l.google.com' % map_addr))

  return result


def V6Mappings():
  """Lookup and store information about the v6 mapping location.

  Return:
    a list of strings, to be added ot the overall result data.
  """
  result = []
  v6_redir = []
  # Find the redirector over v6.
  v6_redir = Resolver('redirector.c.youtube.com', socket.AF_INET6)
  print('v6 redirector sites: %s' % ', '.join(v6_redir))
  result.append('v6 redirector.c.youtube.com: %s' % ', '.join(v6_redir))
  print('Tracerouting to all v6 redir locations in turn.')
  result.append('Traceroute results to v6_redirector destinations.')
  for host in v6_redir:
    result.append(Traceroute(host, '6'))

  # Find the mapping location over v6, returned from the redirector..
  print('Asking for v6 map location.')
  v6_mapping = Wget(url='http://redirector.c.youtube.com/report_mapping',
          family= '6').decode()[:80]
  result.append('v6 mapping:\n%s' % v6_mapping)
  m = MAPPING_RE.match(v6_mapping[:45])
  if m:
    map_addr = m.group(1)
  else:
    print('No mapping address found for ipv6, stopping processing here.')
    return result

  print('v6 Mapping address: %s' % map_addr)
  if '-' in map_addr:
    result.append('Traceroutes to v6 GGC node.\n')
    result.append(Traceroute(map_addr, '6'))

  return result


def main():
  result = []
  v6_redir = []
  map_addr = None
  opts = OptionParser()
  opts.add_option('-e', '--email', default='morrowc.lists@gmail.com',
      dest='email', help='Where should reports be sent?')

  opts.add_option('-f', '--mailfrom', default='morrowc.lists@gmail.com',
      dest='mailfrom', help='Where should reports originate?')

  opts.add_option('-m', '--mailhost', default='mailserver.ops-netman.net',
      dest='mailhost', help='Mailhost to bounce email reports through.')

  (options, args) = opts.parse_args()

  # Get current mappings, v4 first
  result.extend(V4Mappings())

  # v6 if available.
  if socket.has_ipv6:
    print('Tested for v6 connectivity, doing v6 tests.')
    result.extend(V6Mappings())
  else:
    result.append('NO IPv6 AVAILABLE, all v6 tests skipped.')
  
  # Get the hostname/mapping for video playback.
  print('Looking up v4 stream location.')
  loc_v4 = Wget(
          url='"http://redirector.c.youtube.com/videoplayback?id=1&itag=2"',
          family='4',
          output='/dev/null',
          quiet='',
          grep='2>&1 | grep Location | head -1'
          ).decode()
  m = re.search(r'^Location:\s+http://(.+\.youtube\.com)/vid.*$', loc_v4)
  if m:
    loc_v4 = m.group(1)

  print('v4 stream location: %s' % loc_v4.strip())
  result.append('IPv4 streaming host: %s' % loc_v4)

  # Traceroute and save that result as well.
  if loc_v4 != '':
      print('Traceroute to the v4 streamer.')
      print('Streamer: %s' % loc_v4)
      result.append(Traceroute(loc_v4))
  else:
      print('Failed to get a v4 streaming-host address.')

  if socket.has_ipv6:
    loc_v6 = Wget('"http://redirector.c.youtube.com/videoplayback?id=1&itag=2"',
                   '6', '/dev/null', '', '2>&1 | grep Location | head -1').decode()
    m = re.search(r'^Location:\s+http://(.+\.youtube\.com)/vid.*$', loc_v6)
    if m:
      loc_v6 = m.group(1)
    result.append('IPv6 streaming host: %s' % loc_v6)
    if loc_v6 != '':
        print('v6 streamer location: %s' % loc_v6)
        print('Tracerouting to the v6 streaming location.')
        result.append(Traceroute(loc_v6, '6'))
    else:
        print('Failed to get a v6 streaming-host address.')

  print('Emailing results now.')
  EmailResult(options.email, result, options.mailfrom, options.mailhost)


if __name__ == '__main__':
  main()
