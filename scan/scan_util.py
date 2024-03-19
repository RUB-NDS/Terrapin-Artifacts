#!/usr/bin/python3
import json, re
from click import group, option, echo, echo_via_pager, File, Path, progressbar
from ipaddress import ip_address, ip_network
from datetime import datetime
from os import stat

################################################################################
#      Utility script to aggregate zgrab2 scan results (SSH only for now)      #
#                                                                              #
# WARNING: This script may contain lengthy methods and poor python code, but   #
#          does its job. Proceed reading at your own risk ;).                  #
#                                                                              #
# Required pip packages: click>=8.1.7                                          #
#                                                                              #
# Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0 #
################################################################################

@group()
def cli():
  pass

@cli.command(help = 'Filter a zmap file of IP addresses using a zmap-compatible blocklist.')
@option('-b', '--blocklist', type=File('r'), help='A zmap-compatible blocklist which contains one network in CIDR notation per line.', default='blocklist.txt', show_default=True)
@option('-i', '--input', type=Path(exists=True), help='A zmap file of IP addresses with one IP-address per line.', default='zmap.csv', show_default=True)
@option('-o', '--output', type=File('x+'), help='Filtered IP address file which does no longer contain blocked IP addresses.', default='output.csv', show_default=True)
def filter_blocked_ips(blocklist, input, output):
  bl = [ ip_network(cidr.strip()) for cidr in blocklist ]
  with open(input, 'r') as in_ptr:
    with progressbar(length = stat(input).st_size, label='Filtering blocked IP addresses') as bar:
      for line in in_ptr:
        ip = ip_address(line.strip())
        if any([ (ip in blocked_range) for blocked_range in bl ]):
          echo_via_pager(f'Filtered blocked ip address: {ip}')
        else:
          output.write(line)
        bar.update(len(line.encode('utf-8')))

@cli.command(help = 'Filter a zgrab2 file of scan results by removing any line indicating a connection failure. This can be useful to reduce the overall file size for further evaluation.')
@option('-i', '--input', type=Path(exists=True), help='A zgrab2 file of scan results to process.', default='zgrab2.json', show_default=True)
@option('-o', '--output', type=File('x+', 'utf-8'), help='Output file which contains only successful connection from the input file.', default='zgrab2.filtered.json', show_default=True)
@option('-m', '--module', help='The zgrab2 module used to gather the results. If multiple modules have been used during the scan, the script will filter the results based on this module only.', default='ssh', show_default=True)
@option('--keep-unknown-errors', is_flag=True, help='If provided lines indicating unknown errors will not be removed in the resulting file.')
@option('--keep-connection-timeouts', is_flag=True, help='If provided lines indicating connection timeouts will not be removed in the resulting file.')
def tidy_zgrab2(input, output, module, keep_unknown_errors, keep_connection_timeouts):
  with open(input, mode='r', encoding='utf-8') as in_ptr:
    with progressbar(length = stat(input).st_size, label='Tidying zgrab2 results file') as bar:
      for line in in_ptr:
        try:
          scan_result = json.loads(line)
          status = scan_result['data'][module]['status']
          if (status == 'success' or
              (keep_unknown_errors and status == 'unknown-error') or 
              (keep_connection_timeouts and status == 'connection-timeout') or
              # Keep line if scan result indicates an unknown error but the SSH version exchange completed successfully
              (module == 'ssh' and status == 'unknown-error' and 'server_id' in scan_result['data'][module]['result'] and 'version' in scan_result['data'][module]['result']['server_id'])):
            output.write(line)
        except json.JSONDecodeError:
          echo_via_pager(f'Encountered invalid json while cleaning scan results, line will be skipped: {line}')
        finally:
          bar.update(len(line.encode('utf-8')))

@cli.command(help = 'Evaluate a zgrab2 file of scan results by aggregating the results. Make sure to keep the original file as A LOT of information is going to get lost in the process.')
@option('-i', '--input', type=Path(exists=True), help='A zgrab2 file of scan results to process.', default='zgrab2.json', show_default=True)
@option('-o', '--output', type=File('x+', 'utf-8'), help='Output file where the aggregated scan results will be stored to.', default='zgrab2.acc.json', show_default=True)
@option('-m', '--module', help='The zgrab2 module used to gather the results. If multiple modules have been used during the scan, only the specified module will be evaluted.', default='ssh', show_default=True)
@option('--anonymize', is_flag=True, help='If set, the aggregated results will be filtered to not contain fields with potential personal data. For example, banner comments will be excluded.')
def evaluate(input, output, module, anonymize):
  if module == 'ssh':
    evaluate_ssh(input, output, anonymize)
  else:
    echo('Only SSH evaluation is supported at the moment!', fg='red', err=True)
    return

def increment(dict, key, increment = 1):
  if key in dict:
    dict[key] += increment
  else:
    dict[key] = increment

def create_empty_ssh_eval_result():
  return {
    #* Date and time of the earliest entry in the zgrab2 results file
    'scan_start': None,
    #* Date and time of the most recent entry in the zgrab2 results file
    'scan_end': None,
    #* Date and time when the evaluation script was started
    'eval_start': datetime.now(),
    #* Date and time when the evaluation script finished processing the results file
    'eval_end': None,
    #* Whether or not this report has been anonymized
    'anonymized': False,
    #* Total host count,
    'total_host_count': 0,
    'ssh': {
      #* This dict tracks the total success and failure status counts.
      # The dict keys represent the status returned by ZGrab2 and the value is the number of occurrences in the results file.
      'status': {},
      #* This dict tracks the different SSH versions found.
      # The dict keys represent the ssh version given in the client identifier and the value is the number of occurrences in the results file.
      'versions': {},
      #* This dict tracks all key exchange related results with nested dicts.
      # Each nested dicts' keys represent the algorithm and the value is the number of occurrences in the results file.
      'kex': {
        # Supported algorithms (all algorithms in name-list)
        'supported': {
          'kex_algorithms': {},
          'host_key_algorithms': {},
          'client_to_server_ciphers': {},
          'server_to_client_ciphers': {},
          'client_to_server_macs': {},
          'server_to_client_macs': {},
          'client_to_server_compression': {},
          'server_to_client_compression': {}
        },
        # Supported BPP modes (currently only c2s name-lists are analyzed)
        'supported_modes': {
          'chacha20_poly1305': 0,
          'gcm': 0,
          'ctr_etm': 0,
          'ctr_eam': 0,
          'cbc_etm': 0,
          'cbc_eam': 0,
          'stream_etm': 0,
          'stream_eam': 0
        },
        # Supported cipher families (WIP)
        'supported_cipher_families': {
          'aes-gcm': 0,
          'aes-ctr': 0,
          'aes-cbc': 0,
          'chacha20-poly1305': 0,
          '3des-cbc': 0,
          '3des-ctr': 0,
          'twofish-ctr': 0,
          'twofish-cbc': 0,
          'blowfish-ctr': 0,
          'blowfish-cbc': 0,
          'cast128-ctr': 0,
          'cast128-cbc': 0,
          'rc4': 0,
          'des-cbc': 0,
          'idea-ctr': 0,
          'idea-cbc': 0,
          'serpent-ctr': 0,
          'serpent-ctr': 0,
          'none': 0
        },
        # Preferred algorithms (first in name-list only)
        'preferred': {
          'kex_algorithms': {},
          'host_key_algorithms': {},
          'client_to_server_ciphers': {},
          'server_to_client_ciphers': {},
          'client_to_server_macs': {},
          'server_to_client_macs': {},
          'client_to_server_compression': {},
          'server_to_client_compression': {}
        },
        # Preferred BPP modes (currently only c2s name-lists are analyzed)
        'preferred_modes': {
          'chacha20_poly1305': 0,
          'gcm': 0,
          'ctr_etm': 0,
          'ctr_eam': 0,
          'cbc_etm': 0,
          'cbc_eam': 0,
          'stream_etm': 0,
          'stream_eam': 0,
          'unknown': 0
        },
        'preferred_cipher_families': {
          'aes-gcm': 0,
          'aes-ctr': 0,
          'aes-cbc': 0,
          'chacha20-poly1305': 0,
          '3des-cbc': 0,
          '3des-ctr': 0,
          'twofish-ctr': 0,
          'twofish-cbc': 0,
          'blowfish-ctr': 0,
          'blowfish-cbc': 0,
          'cast128-ctr': 0,
          'cast128-cbc': 0,
          'rc4': 0,
          'des-cbc': 0,
          'idea-ctr': 0,
          'idea-cbc': 0,
          'serpent-ctr': 0,
          'serpent-ctr': 0,
          'none': 0,
          'other': 0
        },
        'terrapin': {
          'vulnerable_supported': 0,
          'vulnerable_preferred': 0,
          'exploitable_supported': 0,
          'exploitable_preferred': 0
        }
      },
      #* This dict tracks supported user authentication methods.
      'userauth': {},
      #* This dict tracks the different SSH server implementations found.
      'software': {
        # Each object within this map adheres to the following interface:
        # {
        #   'count': 1,
        #   'comment_strings': { }
        # }
        'banners': {}
      }
    }
  }

def evaluate_ssh(input_file, output, anonymize):
  eval_result = create_empty_ssh_eval_result()
  with open(input_file, mode='r', encoding='utf-8') as input:
    with progressbar(length = stat(input_file).st_size, label='Evaluating zgrab2 results') as bar:
      line_cnt = 0
      for line in input:
        try:
          line_cnt += 1
          scan_result = json.loads(line)
        except json.JSONDecodeError:
          echo_via_pager(f'Caught a JSONDecodeError while reading the input file, line {line_cnt} will be skipped.')
          continue
        eval_result['total_host_count'] += 1
        # Update scanStart and / or scanEnd
        scan_result['data']['ssh']['timestamp'] = datetime.fromisoformat(scan_result['data']['ssh']['timestamp'])
        if eval_result['scan_start'] is None or eval_result['scan_start'] > scan_result['data']['ssh']['timestamp']:
          eval_result['scan_start'] = scan_result['data']['ssh']['timestamp']
        if eval_result['scan_end'] is None or eval_result['scan_end'] < scan_result['data']['ssh']['timestamp']:
          eval_result['scan_end'] = scan_result['data']['ssh']['timestamp']
        # Status
        increment(eval_result['ssh']['status'], scan_result['data']['ssh']['status'])
        # Continue evaluation if and only if we get got a result
        if ('data' not in scan_result or 
            'ssh' not in scan_result['data'] or 
            'result' not in scan_result['data']['ssh'] or 
            not isinstance(scan_result['data']['ssh']['result'], dict)):
          # Update the progress bar and continue with the next line
          bar.update(len(line.encode('utf-8')))
          continue
        
        #* Server Identification
        if 'server_id' in scan_result['data']['ssh']['result']:
          server_id = scan_result['data']['ssh']['result']['server_id']
          if isinstance(server_id, dict):
            if 'version' in server_id:
              if isinstance(server_id['version'], str):
                # SSH version
                increment(eval_result['ssh']['versions'], server_id['version'])
              else:
                echo_via_pager('server_id.version is present, but of unexpected type')
            if 'version' in server_id and 'software' in server_id:
              if isinstance(server_id['software'], str):
                # Server identification
                if server_id['software'] not in eval_result['ssh']['software']['banners']:
                  eval_result['ssh']['software']['banners'][server_id['software']] = {
                    'count': 0,
                    'comment_strings': {}
                  }
                software = eval_result['ssh']['software']['banners'][server_id['software']]
                software['count'] += 1
                if 'comment' in server_id:
                  if isinstance(server_id['comment'], str):
                    increment(software['comment_strings'], server_id['comment'])
                  else:
                    echo_via_pager('server_id.comment is present, but of unexpected type')
              else:
                echo_via_pager('server_id.software is present, but of unexpected type')
            elif 'software' in server_id:
              echo_via_pager('server_id.software is present, but server_id.version is missing. This indicates a failed handshake with a wrong detection of the software by zgrab2.')
          else:
            echo_via_pager('server_id is present, but of unexpected type')

        #* KEX
        if 'server_key_exchange' in scan_result['data']['ssh']['result']:
          server_kex = scan_result['data']['ssh']['result']['server_key_exchange']
          if isinstance(server_kex, dict):
            # Algorithm lists
            fields_to_evaluate = [ 'kex_algorithms', 'host_key_algorithms', 'client_to_server_ciphers', 'server_to_client_ciphers', 'client_to_server_macs', 'server_to_client_macs', 'client_to_server_compression', 'server_to_client_compression' ]
            for kex_field in fields_to_evaluate:
              evaluate_algorithm_list(eval_result, server_kex, kex_field)
            # BPP modes
            modes_to_evaluate = [ 'chacha20_poly1305', 'gcm', 'ctr_etm', 'ctr_eam', 'cbc_etm', 'cbc_eam', 'stream_etm', 'stream_eam' ]
            any_mode_preferred = False
            for bpp_mode in modes_to_evaluate:
              if check_bpp_mode(server_kex, bpp_mode, True):
                increment(eval_result['ssh']['kex']['preferred_modes'], bpp_mode)
                increment(eval_result['ssh']['kex']['supported_modes'], bpp_mode)
                any_mode_preferred = True
              elif check_bpp_mode(server_kex, bpp_mode):
                increment(eval_result['ssh']['kex']['supported_modes'], bpp_mode)
            if not any_mode_preferred:
              increment(eval_result['ssh']['kex']['preferred_modes'], 'unknown')
            # Terrapin vulnerability (CVE-2023-48795)
            if 'kex_algorithms' in server_kex and 'kex-strict-s-v00@openssh.com' not in server_kex['kex_algorithms']:
              if check_bpp_mode(server_kex, 'chacha20_poly1305', True) or check_bpp_mode(server_kex, 'cbc_etm', True):
                eval_result['ssh']['kex']['terrapin']['exploitable_supported'] += 1
                eval_result['ssh']['kex']['terrapin']['exploitable_preferred'] += 1
                eval_result['ssh']['kex']['terrapin']['vulnerable_supported'] += 1
                eval_result['ssh']['kex']['terrapin']['vulnerable_preferred'] += 1
              elif check_bpp_mode(server_kex, 'chacha20_poly1305') or check_bpp_mode(server_kex, 'cbc_etm'):
                eval_result['ssh']['kex']['terrapin']['exploitable_supported'] += 1
                eval_result['ssh']['kex']['terrapin']['vulnerable_supported'] += 1
              elif check_bpp_mode(server_kex, 'ctr_etm', True) or check_bpp_mode(server_kex, 'stream_etm', True):
                eval_result['ssh']['kex']['terrapin']['vulnerable_supported'] += 1
                eval_result['ssh']['kex']['terrapin']['vulnerable_preferred'] += 1
              elif check_bpp_mode(server_kex, 'ctr_etm') or check_bpp_mode(server_kex, 'stream_etm'):
                eval_result['ssh']['kex']['terrapin']['vulnerable_supported'] += 1
            # Cipher families
            evaluate_cipher_families(eval_result['ssh']['kex'], server_kex)
          else:
            echo_via_pager('server_key_exchange is present, but of unexpected type')

        #* User Authentication Methods
        if 'userauth' in scan_result['data']['ssh']['result']:
          userauth = scan_result['data']['ssh']['result']['userauth']
          if isinstance(userauth, list):
            for method in userauth:
              increment(eval_result['ssh']['userauth'], method)
          else:
            echo_via_pager('userauth is present, but of unexpected type')

        # Update the progress bar
        bar.update(len(line.encode('utf-8')))
  eval_result['eval_end'] = datetime.now()

  # Perform anonymization (if flag has been provided)
  if anonymize:
    eval_result['anonymized'] = True
    for banner in eval_result['ssh']['software']['banners']:
      eval_result['ssh']['software']['banners'][banner]['comment_strings'] = {}

  # Sort the dictionaries by frequency (helps with manual analysis)
  # Requires python 3.7+ which guarantees dict insertion order
  dictValue = lambda item: item[1]
  eval_result['ssh']['versions'] = dict(sorted(eval_result['ssh']['versions'].items(), key=dictValue, reverse=True))
  eval_result['ssh']['software']['banners'] = dict(sorted(eval_result['ssh']['software']['banners'].items(), key=lambda item: item[1]['count'], reverse=True))
  for banner in eval_result['ssh']['software']['banners']:
    eval_result['ssh']['software']['banners'][banner]['comment_strings'] = dict(sorted(eval_result['ssh']['software']['banners'][banner]['comment_strings'].items(), key=dictValue, reverse=True))
  for algType in eval_result['ssh']['kex']['supported']:
    eval_result['ssh']['kex']['supported'][algType] = dict(sorted(eval_result['ssh']['kex']['supported'][algType].items(), key=dictValue, reverse=True))
  for algType in eval_result['ssh']['kex']['preferred']:
    eval_result['ssh']['kex']['preferred'][algType] = dict(sorted(eval_result['ssh']['kex']['preferred'][algType].items(), key=dictValue, reverse=True))
  eval_result['ssh']['kex']['supported_modes'] = dict(sorted(eval_result['ssh']['kex']['supported_modes'].items(), key=dictValue, reverse=True))
  eval_result['ssh']['kex']['supported_cipher_families'] = dict(sorted(eval_result['ssh']['kex']['supported_cipher_families'].items(), key=dictValue, reverse=True))
  eval_result['ssh']['kex']['preferred_modes'] = dict(sorted(eval_result['ssh']['kex']['preferred_modes'].items(), key=dictValue, reverse=True))
  eval_result['ssh']['kex']['preferred_cipher_families'] = dict(sorted(eval_result['ssh']['kex']['preferred_cipher_families'].items(), key=dictValue, reverse=True))
  eval_result['ssh']['userauth'] = dict(sorted(eval_result['ssh']['userauth'].items(), key=dictValue, reverse=True))

  # Dump to output
  def serializeDatetime(obj):
    if isinstance(obj, datetime):
      return obj.isoformat()
    raise TypeError()
  json.dump(eval_result, output, indent=2, default=serializeDatetime)

def evaluate_algorithm_list(eval_result, server_kex, key):
  if key in server_kex:
    if isinstance(server_kex[key], list) and len(server_kex[key]) > 0:
      increment(eval_result['ssh']['kex']['preferred'][key], server_kex[key][0])
      for alg in server_kex[key]:
        increment(eval_result['ssh']['kex']['supported'][key], alg)
    else:
      echo_via_pager(f"server_key_exchange.{key} is present, but of unexpected type")

chacha20_poly1305_regex = re.compile(r'^chacha20-poly1305@openssh\.com$')
gcm_regex = re.compile(r'(-gcm(@.{1,64})?$|^AEAD_AES_(128|256)_GCM$)')
ctr_regex = re.compile(r'-ctr(@.{1,64})?$')
cbc_regex = re.compile(r'-cbc(@.{1,64})?$')
stream_regex = re.compile(r'^arcfour(128|256)?$')

etm_regex = re.compile(r'-etm(@.{1,64})?$')
not_eam_regex = re.compile(r'(-etm(@.{1,64})?$|^AEAD_AES_(128|256)_GCM$)')

def regex_search_any(regex: re.Pattern, str_list: list[str]):
  for s in str_list:
    if regex.search(s):
      return True
  return False

def regex_match_any(regex: re.Pattern, str_list: list[str]):
  for s in str_list:
    if regex.match(s):
      return True
  return False

def check_bpp_mode(server_kex, mode: str, preferred=False):
  if not 'client_to_server_ciphers' in server_kex or not 'client_to_server_macs' in server_kex:
    return False
  c2s_ciphers = server_kex['client_to_server_ciphers']
  c2s_macs = server_kex['client_to_server_macs']
  if not isinstance(c2s_ciphers, list) or not isinstance(c2s_macs, list) or len(c2s_ciphers) == 0:
    return False
  if preferred:
    pref_cipher = c2s_ciphers[0]
    if mode == 'chacha20_poly1305':
      return bool(chacha20_poly1305_regex.search(pref_cipher))
    elif mode == 'gcm':
      return bool(gcm_regex.search(pref_cipher))
    if len(c2s_macs) == 0:
      return False
    pref_mac = c2s_macs[0]
    if mode == 'ctr_etm':
      return bool(ctr_regex.search(pref_cipher)) and bool(etm_regex.search(pref_mac))
    elif mode == 'ctr_eam':
      return bool(ctr_regex.search(pref_cipher)) and not bool(not_eam_regex.search(pref_mac))
    elif mode == 'cbc_etm':
      return bool(cbc_regex.search(pref_cipher)) and bool(etm_regex.search(pref_mac))
    elif mode == 'cbc_eam':
      return bool(cbc_regex.search(pref_cipher)) and not bool(not_eam_regex.search(pref_mac))
    elif mode == 'stream_etm':
      return bool(stream_regex.search(pref_cipher)) and bool(etm_regex.search(pref_mac))
    elif mode == 'stream_eam':
      return bool(stream_regex.search(pref_cipher)) and not bool(not_eam_regex.search(pref_mac))
    else:
      return False
  else:
    if mode == 'chacha20_poly1305':
      return regex_search_any(chacha20_poly1305_regex, c2s_ciphers)
    elif mode == 'gcm':
      return regex_search_any(gcm_regex, c2s_ciphers)
    if len(c2s_macs) == 0:
      return False
    if mode == 'ctr_etm':
      return regex_search_any(ctr_regex, c2s_ciphers) and regex_search_any(etm_regex, c2s_macs)
    elif mode == 'ctr_eam':
      return regex_search_any(ctr_regex, c2s_ciphers) and not regex_search_any(not_eam_regex, c2s_macs)
    elif mode == 'cbc_etm':
      return regex_search_any(cbc_regex, c2s_ciphers) and regex_search_any(etm_regex, c2s_macs)
    elif mode == 'cbc_eam':
      return regex_search_any(cbc_regex, c2s_ciphers) and not regex_search_any(not_eam_regex, c2s_macs)
    elif mode == 'stream_etm':
      return regex_search_any(stream_regex, c2s_ciphers) and regex_search_any(etm_regex, c2s_macs)
    elif mode == 'stream_eam':
      return regex_search_any(stream_regex, c2s_ciphers) and not regex_search_any(not_eam_regex, c2s_macs)
    else:
      return False

def evaluate_cipher_families(result_kex_dict, server_kex):
  pref_other = True
  for cipher_family in cipher_families_regex_map:
    if check_cipher_family(server_kex, cipher_family, True):
      result_kex_dict['preferred_cipher_families'][cipher_family] += 1
      result_kex_dict['supported_cipher_families'][cipher_family] += 1
      pref_other = False
    elif check_cipher_family(server_kex, cipher_family):
      result_kex_dict['supported_cipher_families'][cipher_family] += 1
  if pref_other:
    result_kex_dict['preferred_cipher_families']['other'] += 1

cipher_families_regex_map = {
  'aes-gcm': re.compile(r'^(aes(128|192|256)-gcm@openssh\.com|aes(128|192|256)-gcm|AEAD_AES_(128|256)_GCM)$'),
  'aes-ctr': re.compile(r'^aes(128|192|256)-ctr$'),
  'aes-cbc': re.compile(r'^(aes(128|192|256)-cbc|rijndael-cbc@lysator\.liu\.se|rijndael(128|192|256)-cbc)$'),
  'chacha20-poly1305': re.compile(r'^chacha20-poly1305@openssh\.com$'),
  '3des-ctr': re.compile(r'^3des-ctr$'),
  '3des-cbc': re.compile(r'^3des-cbc$'),
  'twofish-ctr': re.compile(r'^twofish(128|192|256)?-ctr$'),
  'twofish-cbc': re.compile(r'^twofish(128|192|256)?-cbc$'),
  'blowfish-ctr': re.compile(r'^blowfish-ctr$'),
  'blowfish-cbc': re.compile(r'^blowfish-cbc$'),
  'cast128-ctr': re.compile(r'^cast128-ctr$'),
  'cast128-cbc': re.compile(r'^cast128-cbc$'),
  'rc4': re.compile(r'^arcfour(128|256)?$'),
  'des-cbc': re.compile(r'^des-cbc$'),
  'idea-ctr': re.compile(r'^idea-ctr$'),
  'idea-cbc': re.compile(r'^idea-cbc$'),
  'serpent-ctr': re.compile(r'^serpent(128|192|256)-cbc$'),
  'serpent-ctr': re.compile(r'^serpent(128|192|256)-ctr$'),
  'none': re.compile(r'^none$')
}
def check_cipher_family(server_kex, cipher_family: str, preferred=False):
  if not 'client_to_server_ciphers' in server_kex:
    return False
  c2s_ciphers = server_kex['client_to_server_ciphers']
  if not isinstance(c2s_ciphers, list) or len(c2s_ciphers) == 0:
    return False
  if preferred:
    return cipher_families_regex_map[cipher_family].match(c2s_ciphers[0])
  else:
    return regex_match_any(cipher_families_regex_map[cipher_family], c2s_ciphers)

if __name__ == '__main__':
  cli()
