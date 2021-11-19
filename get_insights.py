import bloxone
from datetime import datetime, timedelta, date
import time
import json
import re
from docxtpl import DocxTemplate, InlineImage
from docx import Document
from configparser import ConfigParser
import matplotlib.pyplot as plt
  
configur = ConfigParser()
configur.read('config.ini')

# ** Global Vars **
__version__ = '0.0.1'
__author__ = 'Sif Baksh'
__email__ = 'sbaksh@infoblox.com'
__license__ = 'BSD'

csp_token = 'csp.ini'
version = bloxone.__version__

configur.read(csp_token)
DOC_DATA = {}

DOC_DATA.update({"customer": configur.get('report','customer')})
DOC_DATA.update({"doc_title": configur.get('report','doc_title')})
DOC_DATA.update({"cus_name": configur.get('report','cus_name')})
DOC_DATA.update({"cus_phone": configur.get('report','cus_phone')})
DOC_DATA.update({"cus_email": configur.get('report','cus_email')})
days_ago = configur.get('report','date_ago')

d = datetime.now()
network = "BloxOne Endpoint"

t = bloxone.b1(csp_token)
td = bloxone.b1td(csp_token)

# Obtain current timestamp in Unix ticks, truncate
# Time is UTC
current_ts = int(time.time())
# Go back in time 
delta = d - timedelta(days = int(days_ago))
starttime = int(time.mktime(delta.timetuple()))
print (starttime, current_ts)


def get_insights(insight, body):
    url = t.base_url + insight
    result = t._apipost(url, body)
    if result.status_code in t.return_codes_ok:
        datas = result.json()
    else:
        print(result.text)
        datas = ''

    return datas

url_exfil = "/api/ti-reports/v1/activity/aggregations"
url_insight = "/api/ti-reports/v1/activity/aggregations/insight"
payload_exfil = json.dumps({
  "t0": starttime,
  "t1": current_ts,
  "_filter": "type in ['4']",
  "aggs": [
    {
      "key": "tproperty"
    },
    {
      "key": "user"
    },
    {
      "key": "network"
    }
  ],
  "size": 10000
})

payload_doh = json.dumps({
  "include_count": True,
  "t0": starttime,
  "t1": current_ts,
  "_filter": "type in ['2'] and category == null and severity != 'Low' and severity != 'Info' and feed_name == 'Public_DOH' or feed_name == 'public-doh' or feed_name == 'Public_DOH_IP' or feed_name == 'public-doh-ip'",
  "aggs": [
    {
      "key": "threat_indicator",
      "sub_key": [
        {
          "key": "feed_name"
        },
        {
          "key": "user"
        },
        {
          "key": "device_name"
        }
      ]
    }
  ],
  "size": 10
})

payload_malware = json.dumps({
  "include_count": True,
  "t0": starttime,
  "t1": current_ts,
  "_filter": "type in ['2'] and tclass == 'Malware*'",
  "aggs": [
    {
      "key": "tproperty",
      "sub_key": [
        {
          "key": "device_name"
        },
        {
          "key": "user"
        }
      ]
    }
  ],
  "size": 10
})

payload_cat = json.dumps({
    "include_count": True,
    "t0": starttime,
    "t1": current_ts,
    "_filter": "type in ['3'] and feed_name=='CAT_Mal*' or feed_name=='CAT_Phi*' or feed_name=='CAT_Spam*'",
    "aggs": [
        {
            "key": "feed_name",
            "sub_key": [
                {
                    "key": "device_name"
                },
                {
                    "key": "user"
                }
            ]
        }
    ],
    "size": 20
})

counts = json.dumps({
  "count": False,
  "t0": starttime,
  "t1": current_ts,
  "_filter": "type in ['2','3','4']",
  "aggs": [
    {
      "key": "tclass"
    }
  ],
  "size": 20
})

payload_chart = json.dumps({
  "include_count": True,
  "t0": 1635444000,
  "t1": 1635530399,
  "_filter": "type in ['2']",
  "aggs": [
    {
      "key": "tproperty"
    }
  ],
  "size": 5
})

# Create doc type with variable
def output_doc(type, cc):
    DOC_DATA.update({type: cc })

datas =(get_insights(url_exfil, payload_exfil))
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
#         print(f"\t{ d['key'] } - { d['count'] }")
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
        print(f"\t{ d['key'] } - { d['count'] }")


datas =(get_insights(url_insight, counts))
total_mal_count = 0
for data in datas['results'][0]['sub_bucket']:
  #print(f"{ data['key'] } - { data['count'] }")
  if data['key'] == "Data Exfiltration":
    total_dex_count= data['count']
    DOC_DATA.update({"total_dex_count": total_dex_count})
  if data['key'].find('Malware')!= -1:
    total_mal_count += int(data['count'])
    DOC_DATA.update({"total_mal_count": total_mal_count})

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

url = t.base_url + '/api/ti-reports/v1/activity/hits?t0=' + str(starttime) +'&t1=' + str(current_ts) + '&_limit=100&_offset=0&_format=json'

result = t.get(url)
datas = result.json()
total_events = datas['success']['size']
total_events = int(total_events)
total_events = "{:,}".format(total_events)
DOC_DATA.update({"total_events": total_events})
# This is the template file I'm going to use
doc = DocxTemplate("template_B1TD_report.docx")

# Adding the Chart to the Word Doc
myimage = InlineImage(doc, image_descriptor='threat_view.png')
DOC_DATA.update({"myimage": myimage})

# Populate Template
doc.render(DOC_DATA)
# The output file is 
# doc.save("report5.docx")
doc.save("B1TD_Report_" + (date.today()).strftime("%Y-%m-%d") + "_" + re.sub('[^a-zA-Z0-9]', '_', configur.get('report','customer')) + ".docx")
