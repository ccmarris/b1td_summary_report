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
__version__ = '0.0.5'
__author__ = 'Chris Marrison, Sif Baksh'
__email__ = 'chris@infoblox.com'
__license__ = 'BSD'

import bloxone
import argparse
import configparser
import logging
import datetime
import os
import shutil
import json
import re
import time
import docxtpl
import matplotlib.pyplot as plt
  
# Global Variables
log = logging.getLogger(__name__)


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
            log.info("Outfile exists moved to {}".format(backup))
            try:
                handler = open(filename, mode='w')
                log.info("Successfully opened output file {}.".format(filename))
            except IOError as err:
                log.error("{}".format(err))
                handler = False
        except:
            logging.warning("Could not back up existing file {}, exiting.".format(filename))
            handler = False
    else:
        try:
            handler = open(filename, mode='w')
            log.info("Opened file {} for invalid lines.".format(filename))
        except IOError as err:
            log.error("{}".format(err))
            handler = False

    return handler


def read_ini(ini_filename):
    '''
    Open and parse ini file

    Parameters:
        ini_filename (str): name of inifile

    Returns:
        config (dict): Dictionary of BloxOne configuration elements

    '''
    # Local Variables
    section = 'B1TDC Report'
    cfg = configparser.ConfigParser()
    config = {}
    ini_keys = [ 'b1inifile', 'customer', 'contact',
                 'contact_phone', 'contact_email', 'no_of_days' ]

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
    self.ti_reports = '/api/ti-reports/' + self.cfg['api_version']
    self.aggr_reports  = self.ti_reports + '/activity/aggregations'
    self.insights = self.aggr_reports + '/insight'

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
      unit = delta[1:].lower()

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
        result.update({ 'days': 0 })
    else:
      raise(TypeError)
    
    return result


  def get_insight(self, insight, period="30d",):
    '''
    '''
    delta = {}
    delta = self.convert_time_delta(period)
    now = datetime.datetime.now()
    dt = now - datetime.timedelta(**delta)
    t1 = int(now.timestamp())
    t0 = int(dt.timestamp())

    # Generate body
    if insight == 'dex':
      body = { "t0": starttime, "t1": current_ts,
               "_filter": "type in ['4']",
               "aggs": [ { "key": "tproperty" },
                         { "key": "user" },
                         { "key": "network" } ],
               "size": 10000 }

    if insight == 'doh':
      filter = ( "type in ['2'] and category == null and severity != 'Low' " +
                 "and severity != 'Info' and feed_name == 'Public_DOH' or " +
                 "feed_name == 'public-doh' or feed_name == 'Public_DOH_IP' " +
                 "or feed_name == 'public-doh-ip'" )
      body = { "include_count": True,
                "t0": starttime, "t1": current_ts,
                "_filter": filter,
                "aggs": [ { "key": "threat_indicator",
                           "sub_key": [ { "key": "feed_name" },
                                        { "key": "user" },
                                        { "key": "device_name" } ] 
                         } ],
               "size": 10 } 

    elif insight == 'malware':
      body = { "include_count": True,
               "t0": starttime, "t1": current_ts,
                "_filter": "type in ['2'] and tclass == 'Malware*'",
                "aggs": [ { "key": "tproperty", 
                            "sub_key": [ { "key": "device_name" },
                                         { "key": "user" } ] } ],
                "size": 10 }

    elif insight == 'category':
      filter = ( "type in ['3'] and feed_name=='CAT_Mal*' or " +
                 "feed_name=='CAT_Phi*' or feed_name=='CAT_Spam*'" )
      body = { "include_count": True,
               "t0": starttime, "t1": current_ts,
               "_filter": filter,
               "aggs": [ { "key": "feed_name",
                           "sub_key": [ { "key": "device_name" },
                                        { "key": "user" } ] } ],
               "size": 20 }

    elif insight == 'category':
      body =  { "count": False, "t0": starttime, "t1": current_ts,
                "_filter": "type in ['2','3','4']",
                "aggs": [ { "key": "tclass" } ],
                "size": 20 } 

    elif insight == 'chart':
      body = { "include_count": True,
                        "t0": 1635444000, "t1": 1635530399,
                        "_filter": "type in ['2']",
                        "aggs": [ { "key": "tproperty" } ],
                        "size": 5 }
    
    response = self.post(url, json.dump(body))

    return response



def main():
  '''
  '''
  doc_data = {}

  doc_data.update({"customer": configur.get('report','customer')})
  doc_data.update({"doc_title": configur.get('report','doc_title')})
  doc_data.update({"cus_name": configur.get('report','cus_name')})
  doc_data.update({"cus_phone": configur.get('report','cus_phone')})
  doc_data.update({"cus_email": configur.get('report','cus_email')})
  no_of_days = configur.get('report','date_ago')

  network = "BloxOne Endpoint"

  b1 = bloxone.b1(csp_token)
  b1td = bloxone.b1td(csp_token)

  # Create doc type with variable
  def output_doc(type, cc):
      doc_data.update({type: cc })

  datas =(get_insights(b1, url_exfil, payload_exfil))
  output_doc('data_exfil', datas)
  #for data in datas['results']:
    #print(f"{ data['key'] } - { data['count'] }")

  datas =(get_insights(url_insight, payload_doh))

  # To break out the users and networks later
  # print('Public DoH')
  # for data in datas['results'][0]['sub_bucket']:
  #   print(f"{ data['key'] } - { data['count'] }")
  #   for da in data['sub_bucket']:
  #     #print(f"{ da['key'] } - { da['count'] }")
  #     for d in da['sub_bucket']:
  #       if da['key'] != 'feed_name':
  #         print(f"\b1{ d['key'] } - { d['count'] }")

  output_doc('data_doh', datas)


  datas =(get_insights(url_insight, payload_malware))
  output_doc('data_mal', datas)

  datas_cat =(get_insights(url_insight, payload_cat))
  output_doc('data_cat', datas_cat)

  # To break out the users and networks later
  print('Cat')
  for data in datas_cat['results'][0]['sub_bucket']:
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


  datas =(get_insights(url_insight, counts))
  total_mal_count = 0
  for data in datas['results'][0]['sub_bucket']:
    #print(f"{ data['key'] } - { data['count'] }")
    if data['key'] == "Data Exfiltration":
      total_dex_count= data['count']
      doc_data.update({"total_dex_count": total_dex_count})
    if data['key'].find('Malware')!= -1:
      total_mal_count += int(data['count'])
      doc_data.update({"total_mal_count": total_mal_count})

  list_key =[]
  list_count =[]

  #### Graph code start
  chart =(get_insights(url_insight, payload_chart))

  for data in chart['results'][0]['sub_bucket']:
      print(f"{ data['key'] } - { data['count'] }")
      list_key.append(data['key'])
      list_count.append(int(data['count']))


  plt.xticks(range(len(list_count)), list_key)
  plt.xlabel('Threat Type')
  plt.ylabel('Total')
  plt.title('Top 5 Threat Type')
  plt.xticks(rotation=45)
  plt.subplots_adjust(left=0.2, right=0.9, bottom=0.3, top=0.9)
  plt.bar(range(len(list_count)), list_count, align='center', color=['red', 'orange', 'cyan', 'blue', 'green']) 
  plt.show()
  plt.savefig('threat_view.png')
  #### Graph code ends

  url = b1.base_url + '/api/ti-reports/v1/activity/hits?t0=' + str(starttime) +'&t1=' + str(current_ts) + '&_limit=100&_offset=0&_format=json'

  result = b1.get(url)
  datas = result.json()
  total_events = datas['success']['size']
  total_events = int(total_events)
  total_events = "{:,}".format(total_events)
  doc_data.update({"total_events": total_events})
  # This is the template file I'm going to use
  doc = DocxTemplate("template_B1TD_report.docx")

  # Adding the Chart to the Word Doc
  myimage = InlineImage(doc, image_descriptor='threat_view.png')
  doc_data.update({"myimage": myimage})

  # Populate Template
  doc.render(doc_data)
  # The output file is 
  # doc.save("report5.docx")
  doc.save("B1TD_Report_" + (date.today()).strftime("%Y-%m-%d") + "_" + re.sub('[^a-zA-Z0-9]', '_', configur.get('report','customer')) + ".docx")

  return exitcode

### Main ###
if __name__ == '__main__':
    exitcode = main()
    exit(exitcode)
## End Main ###