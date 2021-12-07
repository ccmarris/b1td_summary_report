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
__version__ = '0.0.10'
__author__ = 'Chris Marrison'
__email__ = 'chris@infoblox.com'
__license__ = 'BSD'

import logging
import b1reporting
import argparse
import configparser
import datetime
import os
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
    parse.add_argument('-c', '--config', type=str, default='report.ini',
                        help="Overide Config file")
    parse.add_argument('-t', '--template', type=str, 
                       default='template_B1TD_report.docx', 
                       help="Overide template file")
    parse.add_argument('-o', '--output', action='store_true', 
                        help="Ouput log to file <customer>.log") 
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
                 'contact_phone', 'contact_email', 'time_period',
                 'prepared_by', 'prepared_email' ]

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
                config[key] = cfg[section][key].strip("'\"<>")
                logging.debug(f'Key {key} found in {ini_filename}: {config[key]}')
            else:
                logging.warning(f'Key {key} not found in {section} section.')
                config[key] = ''
    else:
        logging.warning(f'No {section} Section in config file: {ini_filename}')

    return config


def generate_graph(b1r, time_period, show=False, 
                   save=True, filename='threat_view.png'):
  '''
  '''
  list_key =[]
  list_count =[]

  # *** Graph code start
  logging.info('Retrieving data for graph') 
  response = b1r.get_insight('tproperty', time_period) 
  if response.status_code in b1r.return_codes_ok:
    logging.info('- Graph data retrieved')
    logging.debug(f'{response.json()}')
    # Populate Graph Data
    for data in response.json()['results'][0]['sub_bucket']:
        logging.debug(f"{ data['key'] } - { data['count'] }")
        list_key.append(data['key'])
        list_count.append(int(data['count']))

  # Gernerate graph
  ax = plt.subplot()
  hbar = ax.barh(range(len(list_count)), list_count, align='center', 
                color=['red', 'orange', 'cyan', 'blue', 'green']) 
  ax.set_title('Top 5 Feed Hits')
  ax.set_xlabel('Total Hits')
  ax.set_ylabel('Feed Name')
  ax.set_xscale('log')
  # ax.set_xticks(range(len(list_count)))
  ax.set_yticks(range(len(list_count)), list_key)
  ax.bar_label(hbar)
  # plt.subplots_adjust(left=0.2, right=0.9, bottom=0.3, top=0.9)
  plt.tight_layout()
  logging.info('- Graph generated')
  if show:
    plt.show()
    logging.info('- Graph displayed')
  if save:
    plt.savefig(filename)
    logging.info(f'- Graph saved as {filename}')
  # *** Graph code ends

  return


def main():
  '''
  Core Logic
  '''
  exitcode = 0
  # usefile = False
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
  iso_date = (datetime.date.today()).strftime("%Y-%m-%d")
  # Build document dictionary
  doc_data.update({"doc_title": config.get('doc_title')})
  doc_data.update({"customer": config.get('customer')})
  doc_data.update({"contact": config.get('contact')})
  doc_data.update({"contact_phone": config.get('contact_phone')})
  doc_data.update({"contact_email": config.get('contact_email')})
  doc_data.update({"prepared_by": config.get('prepared_by')})
  doc_data.update({"prepared_email": config.get('prepared_email')})
  doc_data.update({"iso_date": iso_date})

  # Instantiate reporting class
  b1r = b1reporting.b1reporting(b1inifile)

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

  # Define template file to use
  doc = docxtpl.DocxTemplate(args.template)

  # Adding the graph_data to the Word Doc
  myimage = docxtpl.InlineImage(doc, image_descriptor='threat_view.png')
  doc_data.update({"myimage": myimage})

  # Populate Template
  logging.info('Generating document')
  doc.render(doc_data)
  # The output file is 
  # doc.save("report5.docx")
  filename = ("B1TD_Report_" + iso_date + "_" + 
              re.sub('[^a-zA-Z0-9]', '_', config.get('customer')) + ".docx")
  try:
    doc.save(filename)
    logging.info(f'Document {filename} created')
  except:
    logging.error(f'Failed to create document {filename}')
    exitcode = 1

  return exitcode


### Main ###
if __name__ == '__main__':
    exitcode = main()
    exit(exitcode)
## End Main ###