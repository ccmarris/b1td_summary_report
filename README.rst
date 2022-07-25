====================================================
Experimental BloxOne Threat Defense Report Generator
====================================================

| Version: 0.0.12
| Author: Chris Marrison
| Email: chris@infoblox.com

Description
-----------

This script is experimental, using experimental API calls to automatically
generate and summary report for BloxOne Threat Defense as a Word document.

To simplify configuration and allow for user and customer specific
customisation, the scripts utilise simple ini files that can be edited with
your favourite text editor.


Prerequisites
-------------

Python 3.7 or above


Installing Python
~~~~~~~~~~~~~~~~~

You can install the latest version of Python 3.x by downloading the appropriate
installer for your system from `python.org <https://python.org>`_.

.. note::

  If you are running MacOS Catalina (or later) Python 3 comes pre-installed.
  Previous versions only come with Python 2.x by default and you will therefore
  need to install Python 3 as above or via Homebrew, Ports, etc.

  By default the python command points to Python 2.x, you can check this using 
  the command::

    $ python -V

  To specifically run Python 3, use the command::

    $ python3


.. important::

  Mac users will need the xcode command line utilities installed to use pip3,
  etc. If you need to install these use the command::

    $ xcode-select --install

.. note::

  If you are installing Python on Windows, be sure to check the box to have 
  Python added to your PATH if the installer offers such an option 
  (it's normally off by default).


Modules
~~~~~~~

Non-standard modules:

    - bloxone 0.8.5+
    - docxtpl
	- matplotlib

These are specified in the *requirements.txt* file.

The latest version of the bloxone module is available on PyPI and can simply be
installed using::

    pip3 install bloxone --user

To upgrade to the latest version::

    pip3 install bloxone --user --upgrade

Complete list of modules::

	import logging
	import b1reporting
	import argparse
	import configparser
	import datetime
	import os
	import shutil
	import re
	import docxtpl
	import matplotlib.pyplot as plt


Installation
------------

The simplest way to install and maintain the tools is to clone this 
repository::

    % git clone https://github.com/ccmarris/b1td_summary_report

Alternative you can download as a Zip file from github.


Basic Configuration
-------------------

There are two simple inifiles for configuration. Although these can be combined
into a single file with the appropriate sections, these have been kept separate
so that API keys, and the bloxone configuration, is maintained separately from
the report configurations. This helps you maintain a single copy
of your API key that is referenced by multiple scripts.

bloxone.ini
~~~~~~~~~~~

The *bloxone.ini* file is used by the bloxone module to access the bloxone
API. A sample inifile for the bloxone module is shared as *bloxone.ini* and 
follows the following format provided below::

    [BloxOne]
    url = 'https://csp.infoblox.com'
    api_version = 'v1'
    api_key = '<you API Key here>'

Simply create and add your API Key, and this is ready for the bloxone
module used by the automation demo script. This inifile should be kept 
in a safe area of your filesystem and can be referenced with full path
in the demo.ini file.


report.ini
~~~~~~~~~~

The report.ini file references the full path to the bloxone.ini file.
All other fields are used in the document template with the exception of the 
time_period field that supports the 1h, 1d, 1w format. 30 days being the max
due to log sizing.

	[B1TDC Report]
	# Full path to bloxone module inifile with API key
	b1inifile = bloxone.ini

	# Report Elements
	doc_title = BloxOne Threat Defense Summary Report
	customer = customer name
	contact = customer contact
	contact_phone = contact phone number
	contact_email = contact email address
	time_period = 30d

	prepared_by = account contact
	prepared_email = account contact email


.. note:: 

    As can be seen the demo inifile references the bloxone.ini file by default
    in the current working directory with the key b1inifile. It is suggested
    that you modify this with the full path to your bloxone ini file.

    For example, *b1inifile = /Users/<username>/configs/bloxone.ini*


Usage
-----

The script supports -h or --help on the command line to access the options 
available::

	% ./b1td_summary_report.py --help
	usage: b1td_summary_report.py [-h] [-c CONFIG] [-t TEMPLATE] [-o] [-d]

	Experimental B1TD Report Generator

	optional arguments:
	-h, --help            show this help message and exit
	-c CONFIG, --config CONFIG
							Overide Config file
	-t TEMPLATE, --template TEMPLATE
							Overide template file
	-o, --output          Ouput log to file <customer>.log
	-d, --debug           Enable debug messages


For example::

    % ./b1td_summary_report.py --help
    % ./b1td_summary_report.py -c <path to inifile> 
    % ./b1td_summary_report.py -c report.ini -t B1TD_report_template.docx
    

License
-------

This project, and the bloxone module are licensed under the 2-Clause BSD License
- please see LICENSE file for details.


Aknowledgements
---------------

Thanks to Sif Baksh for the original prototype on which some of the code is based.