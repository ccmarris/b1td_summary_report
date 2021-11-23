#!/usr/local/bin/python3
#vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''

 Description:

    Generate Standardised B1TDC Report as Word DOC

 Requirements:
  Python 3.7+
  bloxone module
  matplotlib
  docxtpl

 Author: Chris Marrison, based on prototype script by Sif Baksh

 Date Last Updated: 20211119

 Todo:

 Copyright (c) 2021 Chris Marrison / Infoblox

'''
__version__ = '0.0.8'
__author__ = 'Chris Marrison, Sif Baksh'
__email__ = 'chris@infoblox.com'
__license__ = 'BSD'

import logging
import bloxone
import argparse
import configparser
import datetime
import os
import sys
import shutil
import json
import re
import docxtpl
import matplotlib.pyplot as plt
  
# Global Variables
# log = logging.getLogger(__name__)
# log.addHandler(console_handler)


def parseargs():
    '''
    Parse Arguments Using argparse

    Parameters:
        None

    Returns:
        Returns parsed arguments
    '''
    parse = argparse.ArgumentParser(description='SE Automation Demo - Create Demo')
    parse.add_argument('-o', '--output', action='store_true', 
                        help="Ouput log to file <customer>.log") 
    parse.add_argument('-c', '--config', type=str, default='csp.ini',
                        help="Overide Config file")
    parse.add_argument('-d', '--debug', action='store_true', 
                        help="Enable debug messages")

    return parse.parse_args()


def setup_logging(debug=False, usefile=False):
    '''
     Set up logging

     Parameters:
        advanced (bool): True or False.

     Returns:
        None.

    '''

    # Set advanced level
    # if level == "advanced":
     #    logging.addLevelName(15, "advanced")
      #   logging.basicConfig(level=advanced,
       #                      format='%(asctime)s %(levelname)s: %(message)s')
    if debug:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s: %(message)s')
    else:
        if usefile:
            # Full log format
            logging.basicConfig(level=logging.INFO,
                                format='%(asctime)s %(levelname)s: %(message)s')
        else:
            # Simple log format
            logging.basicConfig(level=logging.INFO,
                                format='%(levelname)s: %(message)s')

    return


def open_file(filename):
    '''
    Attempt to open output file

    Parameters:
        filename (str): desired filename

    Returns file handler
        handler (file): File handler object
    '''
    if os.path.isfile(filename):
        backup = filename+".bak"
        try:
            shutil.move(filename, backup)
            logging.info("Outfile exists moved to {}".format(backup))
            try:
                handler = open(filename, mode='w')
                logging.info("Successfully opened output file {}.".format(filename))
            except IOError as err:
                logging.error("{}".format(err))
                handler = False
        except:
            logging.warning("Could not back up existing file {}, exiting.".format(filename))
            handler = False
    else:
        try:
            handler = open(filename, mode='w')
            logging.info("Opened file {} for invalid lines.".format(filename))
        except IOError as err:
            logging.error("{}".format(err))
            handler = False

    return handler


def read_ini(ini_filename):
    '''
    Open and parse ini file

    Parameters:
        ini_filename (str): name of inifile

    Returns:
        config (dict): Dictionary of BloxOne configation elements

    '''
    # Local Variables
    section = 'B1TDC Report'
    cfg = configparser.ConfigParser()
    config = {}
    ini_keys = [ 'b1inifile', 'doc_title', 'customer', 'contact',
                 'contact_phone', 'contact_email', 'time_period' ]

    # Attempt to read api_key from ini file
    try:
        cfg.read(ini_filename)
    except configparser.Error as err:
        logging.error(err)

    # Look for demo section
    if section in cfg:
        config['filename'] = ini_filename
        for key in ini_keys:
            # Check for key in BloxOne section
            if key in cfg[section]:
                config[key] = cfg[section][key].strip("'\"")
                logging.debug(f'Key {key} found in {ini_filename}: {config[key]}')
            else:
                logging.warning(f'Key {key} not found in {section} section.')
                config[key] = ''
    else:
        logging.warning(f'No {section} Section in config file: {ini_filename}')

    return config


class b1reporting(bloxone.b1):
  '''
  '''
  def __init__(self, cfg_file='config.ini'):
    '''
    Call base __init__ and extend
    '''
    super().__init__(cfg_file)
    self.ti_reports_url = self.base_url + '/api/ti-reports/' + self.cfg['api_version']
    self.aggr_reports_url  = self.ti_reports_url + '/activity/aggregations'
    self.insights_url = self.aggr_reports_url + '/insight'
    self.sec_act_url = self.base_url + '/api/ti-reports/v1/activity/hits'

    return


  def convert_time_delta(self, delta):
    '''
    Convert digit/unit e.g. 1d to dict

    Parameters:
      delta (str): 
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
    '''
    delta = self.convert_time_delta(period)
    now = datetime.datetime.now()
    dt = now - datetime.timedelta(**delta)
    t1 = int(now.timestamp())
    t0 = int(dt.timestamp())

    # Build url
    url = ( self.sec_act_url + '?t0=' + str(t0) +'&t1=' + str(t1) + 
            '&_limit=100&_offset=0&_format=json' )
    url = self._add_params(url, **params)
    logging.debug("URL: {}".format(url))

    response = self._apiget(url)

    return response


  def get_insight(self, insight, period="1w"):
    '''
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
    if insight == 'dex':
      url = self.aggr_reports_url
      body = { "t0": t0, "t1": t1,
               "_filter": "type in ['4']",
               "aggs": [ { "key": "tproperty" },
                         { "key": "user" },
                         { "key": "network" } ],
               "size": 10000 }

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

    elif insight == 'counts':
      body =  { "count": False, "t0": t0, "t1": t1,
                "_filter": "type in ['2','3','4']",
                "aggs": [ { "key": "tclass" } ],
                "size": 20 } 

    elif insight == 'chart':
      body = { "include_count": True,
                        "t0": t0, "t1": t1,
                        "_filter": "type in ['2']",
                        "aggs": [ { "key": "tproperty" } ],
                        "size": 5 }
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
    response = self.get_insight('counts', time_period)
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

def generate_graph(b1r, time_period):
  '''
  '''
  list_key =[]
  list_count =[]

  # *** Graph code start
  logging.info('Retrieving data for graph')
  response = b1r.get_insight('chart', time_period)
  if response.status_code in b1r.return_codes_ok:
    logging.info('- Graph data retrieved')
    logging.debug(f'{response.json()}')
    # Populate Graph Data
    for data in response.json()['results'][0]['sub_bucket']:
        print(f"{ data['key'] } - { data['count'] }")
        list_key.append(data['key'])
        list_count.append(int(data['count']))

  # Gernerate graph
  plt.xticks(range(len(list_count)), list_key)
  plt.xlabel('Threat Type')
  plt.ylabel('Total')
  plt.title('Top 5 Threat Type')
  plt.xticks(rotation=45)
  plt.subplots_adjust(left=0.2, right=0.9, bottom=0.3, top=0.9)
  plt.bar(range(len(list_count)), list_count, align='center', 
                color=['red', 'orange', 'cyan', 'blue', 'green']) 
  # plt.show()
  plt.savefig('threat_view.png')
  logging.info('- Graph generated')
  # *** Graph code ends

  return


def main():
  '''
  Core Logic
  '''
  exitcode = 0
  usefile = False
  doc_data = {}

  args = parseargs()
  config = read_ini(args.config)
  b1inifile = config['b1inifile']
  time_period = config.get('time_period')

  if config['b1inifile']:
      b1inifile = config['b1inifile']
  else:
      # Try to use inifile
      b1inifile = args.config

  if args.debug:
    logging.getLogger().setLevel(logging.DEBUG) 
  else:
    logging.getLogger().setLevel(logging.INFO) 

  logging.info('Configuration read.')
  # Build document dictionary
  doc_data.update({"doc_title": config.get('doc_title')})
  doc_data.update({"customer": config.get('customer')})
  doc_data.update({"contact": config.get('contact')})
  doc_data.update({"contact_phone": config.get('contact_phone')})
  doc_data.update({"contact_email": config.get('contact_email')})

  # Instantiate reporting class
  b1r = b1reporting(b1inifile)

  # Get core insights - note data is processed in doc template
  insights = [ 'dex', 'doh', 'malware', 'category' ]
  for insight in insights:
    section_name = 'data_' + insight
    logging.info(f'Retrieving {insight} data')
    response = b1r.get_insight(insight, time_period)
    if response.status_code in b1r.return_codes_ok:
      logging.info(f' - {insight} data retrieved')
      report_data = response.json()
    else:
      logging.error(f'Error for {insight} report.')
      logging.info(f'HTTP Code: {response.status_code}')
      logging.info(f'Response: {response.text}')
      report_data = {}
      exitcode = 1
    doc_data.update({ section_name: report_data })

  '''
  Unneeded example code
  #for data in report['results']:
    #print(f"{ data['key'] } - { data['count'] }")

  # To break out the users and networks later
  # print('Public DoH')
  # for data in report['results'][0]['sub_bucket']:
  #   print(f"{ data['key'] } - { data['count'] }")
  #   for da in data['sub_bucket']:
  #     #print(f"{ da['key'] } - { da['count'] }")
  #     for d in da['sub_bucket']:
  #       if da['key'] != 'feed_name':
  #         print(f"\b1{ d['key'] } - { d['count'] }")


  # To break out the users and networks later
  print('Categories')
  for data in doc_data['data_category']['results'][0]['sub_bucket']:
    print(f"{ data['key'] } - { data['count'] }")
    for da in data['sub_bucket']:
      #print(f"{ da['key'] } - { da['count'] }")
      if da['key'] == 'user':
        print("User")
      if da['key'] == 'device_name':
        print("Device")
      for d in da['sub_bucket']:
        if da['key'] != 'feed_name':
          print(f"\b1{ d['key'] } - { d['count'] }")
  '''

  # Add total security hit counts
  doc_data.update(b1r.get_counts(time_period))
 
  # Generate graph
  generate_graph(b1r, time_period)

  # Get total number of security hits
  total_events = b1r.get_total_hits(time_period)
  doc_data.update({ "total_events": total_events })

  # This is the template file I'm going to use
  doc = docxtpl.DocxTemplate("template_B1TD_report.docx")

  # Adding the Chart to the Word Doc
  myimage = docxtpl.InlineImage(doc, image_descriptor='threat_view.png')
  doc_data.update({"myimage": myimage})

  # Populate Template
  doc.render(doc_data)
  # The output file is 
  # doc.save("report5.docx")
  filename = ("B1TD_Report_" + (datetime.date.today()).strftime("%Y-%m-%d") + 
              "_" + re.sub('[^a-zA-Z0-9]', '_', config.get('customer')) + 
              ".docx")
  doc.save(filename)

  return exitcode


### Main ###
if __name__ == '__main__':
    exitcode = main()
    exit(exitcode)
## End Main ###