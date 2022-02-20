#!/usr/local/bin/python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''
------------------------------------------------------------------------

 Description:

 Module to provide class hierachy to simplify access to the BloxOne APIs

 Date Last Updated: 20211203

 Todo:

 Copyright (c) 2021 Chris Marrison / Infoblox

 Redistribution and use in source and binary forms,
 with or without modification, are permitted provided
 that the following conditions are met:

 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

------------------------------------------------------------------------
'''
import logging
import bloxone
import datetime
import json

__version__ = '0.0.3'
__author__ = 'Chris Marrison'
__author_email__ = 'chris@infoblox.com'

class b1reporting(bloxone.b1):
  '''
  Experimental Reporting Class

  ..Note::
    This class uses undocumented API calls that may change without notice
  
  '''
  def __init__(self, cfg_file='config.ini'):
    '''
    Call base __init__ and extend
    '''
    super().__init__(cfg_file)
    self.dns_events_url = self.base_url + '/api/dnsdata/v2'
    self.ti_reports_url = self.base_url + '/api/ti-reports/' + self.cfg['api_version']
    self.aggr_reports_url  = self.ti_reports_url + '/activity/aggregations'
    self.insights_url = self.aggr_reports_url + '/insight'
    self.sec_act_url = self.base_url + '/api/ti-reports/v1/activity/hits'

    return


  def convert_time_delta(self, delta):
    '''
    Convert digit/unit e.g. 1d to dict

    Parameters:
      delta (str): period 3d, 2w, 1m, i.e. \d*[dwm]
    
    Returns:
      dict in form to pass to datetime
    '''
    result = {}
    if isinstance(delta, str):
      no_of = int(delta[:-1])
      unit = delta[-1:].lower()

      if unit in ['d', 'w', 'm']:
        if unit == 'd':
          result.update({ 'days': no_of })
        elif unit == 'w':
          result.update({ 'weeks': no_of })
        elif unit == 'm':
          no_of = 4 * no_of
          result.update({ 'weeks': no_of })
      else:
        logging.error(f'Unit must be one of d:days, w:weeks, m:months not {unit}')
        result.update({ 'days': 1 })
    else:
      raise(TypeError)
    
    return result


  def security_activity(self, period="1d", **params):
    '''
    Get security activity log for specified period

    Parameters:
      period(str): Period in form of 3d, 2w, 1d
    
    Returns:
        requests response object
    '''
    delta = self.convert_time_delta(period)
    now = datetime.datetime.now()
    dt = now - datetime.timedelta(**delta)
    t1 = int(now.timestamp())
    t0 = int(dt.timestamp())

    # Build url
    url =  self.sec_act_url + '?t0=' + str(t0) +'&t1=' + str(t1)
    url = self._add_params(url, **params)
    logging.debug("URL: {}".format(url))

    response = self._apiget(url)

    return response


  def dns_events(self, period='1d', source='', **params):
    '''
    Get DNS events log for specified period

    Parameters:
      period(str): Period in form of 3d, 2w, 1d
    
    Returns:
        requests response object
    '''
    sources = [ 'rpz', 'category', 'analytics' ]
    delta = self.convert_time_delta(period)
    now = datetime.datetime.now()
    dt = now - datetime.timedelta(**delta)
    t1 = int(now.timestamp())
    t0 = int(dt.timestamp())

    url = self.dns_events_url + f'?t0={t0}&t1={t1}'
    
    if source:
      url = url + f'&source={source}'
      if source not in sources:
        logging.warning(f'Unexpected source: {source} check response.')
    # Add additional parameters
    url = self._add_params(url, first_param=False, **params)
    logging.debug(f'dns_events URL: {url}')
    
    response = self._apiget(url)

    return response


  def get_insight(self, insight, period="1w"):
    '''
    Get "insight" summaries

    Parameters:
      insight(str): One of ['activity', 'total_queries', 'doh', 'malware',
                            'category', 'tclass', 'tproperty', 'dex']
      period(str): Period in form of 3d, 2w, 1d
    
    Returns:
        requests response object

    '''
    body = {}
    delta = {}
    delta = self.convert_time_delta(period)
    now = datetime.datetime.now()
    dt = now - datetime.timedelta(**delta)
    t1 = int(now.timestamp())
    t0 = int(dt.timestamp())
    url = self.insights_url

    # Generate body
    if insight == 'activity':
      body = { "include_count": True, "t0": t0, "t1": t1,
               "_filter": "type in ['2', '3'] and severity != 'Info'",
               "aggs": [ { "key": "severity" } ],
               "size": 3 }

    elif insight == 'total_queries':
      body = { "include_count": True, 
               "t0": t0, "t1": t1,
               "_filter": "type in ['1']",
               "aggs": [ { "key": "type", 
                          "sub_key": [ { "key": "policy_action" } ] } ],
               "size": 1 }

    elif insight == 'doh':
      filter = ( "type in ['2'] and category == null and severity != 'Low' " +
                 "and severity != 'Info' and feed_name == 'Public_DOH' or " +
                 "feed_name == 'public-doh' or feed_name == 'Public_DOH_IP' " +
                 "or feed_name == 'public-doh-ip'" )
      body = { "include_count": True,
                "t0": t0, "t1": t1,
                "_filter": filter,
                "aggs": [ { "key": "threat_indicator",
                           "sub_key": [ { "key": "feed_name" },
                                        { "key": "user" },
                                        { "key": "device_name" } ] 
                         } ],
               "size": 10 } 

    elif insight == 'malware':
      body = { "include_count": True,
               "t0": t0, "t1": t1,
                "_filter": "type in ['2'] and tclass == 'Malware*'",
                "aggs": [ { "key": "tproperty", 
                            "sub_key": [ { "key": "device_name" },
                                         { "key": "user" } ] } ],
                "size": 10 }

    elif insight == 'category':
      filter = ( "type in ['3'] and feed_name=='CAT_Mal*' or " +
                 "feed_name=='CAT_Phi*' or feed_name=='CAT_Spam*'" )
      body = { "include_count": True,
               "t0": t0, "t1": t1,
               "_filter": filter,
               "aggs": [ { "key": "feed_name",
                           "sub_key": [ { "key": "device_name" },
                                        { "key": "user" } ] } ],
               "size": 20 }

    elif insight == 'tclass':
      body =  { "count": False, "t0": t0, "t1": t1,
                "_filter": "type in ['2','3','4']",
                "aggs": [ { "key": "tclass" } ],
                "size": 20 } 

    elif insight == 'tproperty':
      body = { "include_count": True,
                        "t0": t0, "t1": t1,
                        "_filter": "type in ['2']",
                        "aggs": [ { "key": "tproperty" } ],
                        "size": 5 }

    elif insight == 'dex':
      url = self.aggr_reports_url
      body = { "t0": t0, "t1": t1,
               "_filter": "type in ['4']",
               "aggs": [ { "key": "tproperty" },
                         { "key": "user" },
                         { "key": "network" } ],
               "size": 10000 }

    elif insight == 'indicator_client_count':
      filter = ( "type in ['2'] and category == null and severity != 'Low' " +
                 "and severity != 'Info'" )
      body = { "include_count": True,
                "t0": t0, "t1": t1,
                "_filter": filter,
                "aggs": [ { "key": "threat_indicator",
                           "sub_key": [ { "key": "feed_name" },
                                        { "key": "user" },
                                        { "key": "device_name" } ] 
                         } ],
               "size": 10 } 
    else:
      logging.error(f'{insight} report not currently supported')
      body = {}
    
    logging.debug(f'URL: {url}, Body: {body}')
    response = self._apipost(url, json.dumps(body), headers=self.headers)
    logging.debug(f'{response.json()}')

    return response

  def get_counts(self, time_period):
    '''
    '''
    counts = {}
    total_dex_count = 0
    total_mal_count = 0
    
    logging.info('Retrieving security hits')
    response = self.get_insight('tclass', time_period)
    if response.status_code in self.return_codes_ok:
      logging.info(f' - security hits retrieved')
      logging.debug(f'{response.json()}')
      for data in response.json()['results'][0]['sub_bucket']:
        #print(f"{ data['key'] } - { data['count'] }")
        if 'Data Exfiltration' in data['key']:
          total_dex_count += int(data['count'])
        if 'Malware' in data['key']:
          total_mal_count += int(data['count'])
    else:
        logging.error(f'Error retrieving security hits.')
        logging.info(f'HTTP Code: {response.status_code}')
        logging.info(f'Response: {response.text}')
        total_dex_count = -1
        total_mal_count = -1
    
    # Add totals to dict
    counts.update({"total_dex_count": total_dex_count})
    counts.update({"total_mal_count": total_mal_count})
    logging.debug(f'Counts: {counts}')

    return counts
 
  def get_total_hits(self, time_period):
    '''
    '''
    response = self.security_activity(time_period)
    if response.status_code in self.return_codes_ok:
      logging.debug(f'response.json()')
      total_events = response.json()['success']['size']
      total_events = int(total_events)
      total_events = "{:,}".format(total_events)
    else:
      logging.error(f'Error retrieving security activity.')
      logging.info(f'HTTP Code: {response.status_code}')
      logging.info(f'Response: {response.text}')
      total_events = -1
    
    return total_events

# End of class