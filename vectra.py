import requests
import json
import io

host="https://x.x.x.x"
token =  "Token xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
category = "" #command botnet reconnaissance lateral exfiltration info
filter = "page_size" #blank or set to include filter tags
filterValue = "5000"
strOutPath = "c:\\test\\vectra.txt" #output file path
boolWriteHeaderRow = False
boolLogJSON = True #Splunk importable output. 
listExclusion = ["1.1.1.1","2.2.2.2"] #Provide a list of full IP addresses to be excluded from csv output. Example: ["10.10.10.10","10.10.10.11"]
boolExcludeDest = True #exclude results if the dest IP matches above
boolLoadJSONfromFile = False
jSONfilePath= 'c:\\test\\vectra_output.json' #output can be consumed by this script via boolLoadJSONfromFile=True. Useful for debugging script

def jsonValue(jsonVal, valueStr):
  if valueStr in jsonVal:
    return jsonVal[valueStr]

def logToFile(strfilePathOut, strDataToLog, boolDeleteFile, strWriteMode):
    with open(strfilePathOut, strWriteMode) as target:
      if boolDeleteFile == True:
        target.truncate()
      target.write(strDataToLog)


def callAPI(strApiURL):
  if strApiURL == None:
    return
  response = requests.get(strApiURL, headers={'Authorization':token}, verify=False)
  textBody = response.content.decode("UTF-8")
  if boolLogJSON == True:
    logToFile(strOutPath + "_JSON.txt","," + textBody + "\n", False, "a")
  #print(textBody)
  try:
    return json.loads(textBody)
  except jsonProblem as e:
    print(jsonProblem)


if jSONfilePath== '':
  boolLoadJSONfromFile = False

if category !="" and filter !="" and filterValue != "":
  parameters={"category": category, filter: filterValue}
elif filter !="" and filterValue != "":
  parameters={filter: filterValue}
elif category !="":
  parameters={"category": category}
else:
  parameters={}
if boolLoadJSONfromFile == True and len(jSONfilePath) > 3:
    # Open a file: file
    file = open(jSONfilePath,mode='r')
 
    # read all lines at once
    textBody = file.read()
 
    # close the file
    file.close()
else:
    response = requests.get(host + "/api/v2.2/detections", headers={'Authorization':token}, params=parameters, verify=False)
    textBody = response.content.decode("UTF-8")  #work around to support flat file JSON
if boolLogJSON == True and boolLoadJSONfromFile == False:
  logToFile(strOutPath + "_JSON.txt","[" + textBody + "\n", False, "a")
#print(textBody)

#textBody = "[" +textBody  + "]" #work around to support flat file JSON
JSONreturns = json.loads( textBody)
#processJSON(JSONreturn, strOutPath)

with io.open(strOutPath , "a", encoding="utf-8") as f:
  for JSONreturn in JSONreturns:
    
    qResults =  JSONreturn["results"]
    paginationURL = ""
    if boolWriteHeaderRow ==True:
      strHead = "hostName"  + "," + "src_ip"  + "," +  "externalTargetIP" + "," + "externalTargetDomain" + "," +  "detection_type" + "," +  "first_timestmap" + "," +  "last_timestamp" + "," + "attacker_detail" + ","  + "bytes_received" + ","  + "bytes_sent" + ","  +  "dnsResponse"  + ","  + "t_score"  + ","  + "c_score"  + ","  + "client_name"  + ","  + "client_token"   + ","  + "keyboard_id" + ",\"" + "dst_ports" + "\",\""  + "target_domains" + "\"" + ",\""  + "protocol_ports" + "\"" + "," + "num_attempts" + "," + "num_successes"  + "," + "app_protocol" + "," + "protocol"  + "," + "request" + ",\"" + "accounts" + "\"" + ",\"" + "shares" + "\"" + "," + "realm" + "," + "reason" + "," + "uuid"
      f.write(strHead + "\n")
      boolWriteHeaderRow = False
    while paginationURL != None:
      if paginationURL is None:
        break
      previousURL = paginationURL
      paginationURL =  JSONreturn["next"]
      if boolLoadJSONfromFile == False or len(jSONfilePath) < 3:

        if previousURL != "":
          JSONreturn = callAPI(paginationURL)
          if paginationURL is None:
            break
          elif JSONreturn is None:
            print("JSON is None from URL: " + paginationURL)
            paginationURL = None
          else:
            logToFile(strOutPath + "lastURL.txt",paginationURL, True, "w")
            qResults =  JSONreturn["results"]
      else:
        paginationURL = None
      for connDetail in qResults:
          logToFile(strOutPath + "_testJSON.txt",json.dumps(connDetail) + "\n", False, "a")
          #print(connDetail)
          #print("pause")
          first_timestmap = ""
          last_timestmap = ""
          client_name = ""
          protocol_ports = ""
          dst_ports = ""
          client_token = ""
          keyboard_id = ""
          dnsResponse = ""
          src_ip = ""
          detection_type = connDetail['detection_type']

          if detection_type == "Suspect Domain Activity":
            #print(detection_type)
            dnsResponse = connDetail['grouped_details'][0]['dns_response']
            if dnsResponse is not None and  "," in dnsResponse:
              dnsResponse = "\"" + dnsResponse + "\""
            elif dnsResponse is None:
              dnsResponse = "";
          src_ip = connDetail['src_ip']
          src_Details = connDetail['src_host']
          if src_Details != None:
            hostName = jsonValue(src_Details, 'name')
          t_score = connDetail['t_score']
          c_score = connDetail['c_score']
          if 'protocol_ports' in connDetail['summary']:
            protocol_ports = connDetail['summary']['protocol_ports']
            if len(protocol_ports) > 0:
              protocol_ports = ",".join(protocol_ports)
          grouped_details = connDetail['grouped_details']
          lenDetails = len(grouped_details)
          for x in range(0, lenDetails):
            externalTargetDomain = ""
            externalTargetIP = ""
            dst_ports = ""
            num_attempts =""
            num_successes= ""
            app_protocol = ""
            protocol = ""
            target_domains = ""
            request = ""
            accounts = ""
            shares = ""
            realm = ""
            reason = ""
            uuid = ""
            executed_functions = ""
            grouped_detail = grouped_details[x]
            if 'dst_ports' in grouped_detail:
              dst_ports = grouped_detail['dst_ports']
            if detection_type == "Suspicious Remote Desktop":
              #print(detection_type)
              client_name = grouped_detail["client_name"]
              client_token = grouped_detail["client_token"]
              keyboard_id = grouped_detail["keyboard_id"]
              keyboard_id = keyboard_id + " - " + grouped_detail["keyboard_name"]
            if "external_target" in grouped_detail:
              external_target = grouped_detail["external_target"]
              if external_target is None:
                externalTargetIP = ""
                externalTargetDomain = ""
              else:
                externalTargetIP = external_target["ip"]
                externalTargetDomain = external_target["name"]
            #else:
            #  print(grouped_detail)
            if 'app_protocol' in grouped_detail:
             app_protocol = grouped_detail['app_protocol']

            if app_protocol is None: # jump into events to get protocols
              if len(grouped_detail['events'][0]) > 0:
                if 'target_summary' in grouped_detail['events'][0]:
                  target_summary = grouped_detail['events'][0]['target_summary']
                  if 'app_protocol' in target_summary:
                    app_protocol = target_summary['app_protocol']
                  if 'protocol' in target_summary:
                    protocol = target_summary['protocol']
                if 'request' in grouped_detail['events'][0]:
                  request = grouped_detail['events'][0]['request']


            bytes_received = jsonValue(grouped_detail,"bytes_received")
            bytes_sent= jsonValue(grouped_detail,"bytes_sent")
          
            ja3_hashes= jsonValue(grouped_detail,"ja3_hashes")
            ja3s_hashes= jsonValue(grouped_detail,"ja3s_hashes")
            #session= grouped_detail["session"]
            first_timestmap= jsonValue(grouped_detail,"first_timestamp")
            last_timestamp= jsonValue(grouped_detail,"last_timestamp")
            attacker_detail= jsonValue(grouped_detail,"attacker_detail")
            if attacker_detail is not None:
               attacker_detail = " ".join(attacker_detail)
            else:
              attacker_detail = ""
            dst_ports= jsonValue(grouped_detail,"dst_ports")
            if app_protocol == "" and 'protocol' in grouped_detail:
              app_protocol = grouped_detail['protocol']
            if 'shares' in grouped_detail:
              shares = grouped_detail['shares']
              if shares is not None:
                shares = ",".join(shares)
              else:
                accounts = ""
            if 'accounts' in grouped_detail:
              accounts = grouped_detail['accounts']
              if accounts is not None:
                accounts = ",".join(accounts)
              else:
                accounts = ""
            if accounts == "" and 'dst_accounts' in grouped_detail:
              accountList = grouped_detail['dst_accounts']
              for account in accountList:
                if 'uid' in account and accounts =="":
                  accounts = account['uid']
                elif 'uid' in account:
                  accounts = accounts + " " + account['uid']
            if accounts == "" and 'account_uid' in grouped_detail:
              accounts = grouped_detail['account_uid']
              if accounts is None:
                accounts = ""
            if 'reason' in grouped_detail:
              reason = grouped_detail['reason']
            if 'uuid' in grouped_detail:
              uuid = grouped_detail['uuid']
            if 'realm' in grouped_detail:
              realm =grouped_detail['realm']
            if 'num_attempts' in grouped_detail:
              num_attempts = grouped_detail['num_attempts']
            if 'num_successes' in grouped_detail:
              num_successes = grouped_detail['num_successes']
            if externalTargetIP == "" and "dst_ips" in grouped_detail:
              externalTargetIP = grouped_detail['dst_ips'][0]
            if externalTargetDomain == "" and "target_domains" in grouped_detail:
              if len(grouped_detail['target_domains']) > 0:
                externalTargetDomain = grouped_detail['target_domains'][0]
                target_domains  = ",".join(grouped_detail['target_domains'])
            if 'executed_functions' in grouped_detail:
              if len(grouped_detail['executed_functions']) > 0:
                executed_functions = grouped_detail['executed_functions'][0]
                executed_functions  = ",".join(grouped_detail['executed_functions'])
            if first_timestmap is None and 'first_seen' in grouped_detail:
              first_timestmap = grouped_detail['first_seen']
            elif first_timestmap is None:
              first_timestmap = ""
            if last_timestamp is None  and 'last_seen' in grouped_detail:
              last_timestamp = grouped_detail['last_seen']
            elif last_timestamp is None:
              last_timestamp = ""
            if bytes_received is None:
              bytes_received = ""
            if bytes_sent is None:
              bytes_sent = ""
            if dst_ports is None:
              dst_ports = ""
            if app_protocol is None:
              app_protocol = ""
            if externalTargetDomain is None:
              externalTargetDomain = ""
            if externalTargetDomain == "" and "dst_hosts" in grouped_detail:
              if len(grouped_detail['dst_hosts']) > 0:
                if 'dst_dns' in grouped_detail['dst_hosts'][0]:
                  externalTargetDomain= grouped_detail['dst_hosts'][0]['dst_dns']
                if 'name' in grouped_detail['dst_hosts'][0]:
                  externalTargetDomain= grouped_detail['dst_hosts'][0]['name']
            if externalTargetDomain == "" and "origin_domain" in grouped_detail:
               externalTargetDomain= grouped_detail['origin_domain']
            #if detection_type == 'Kerberos Brute-Sweep':
            #  print(src_ip)
            if len(listExclusion) > 0:
              if src_ip in listExclusion: #exclusions
                continue
              elif boolExcludeDest == True and externalTargetIP in listExclusion:
                continue
            strOut = hostName  + "," + src_ip  + "," +  externalTargetIP + "," + externalTargetDomain + "," +  detection_type + "," +  first_timestmap + "," +  last_timestamp + "," + attacker_detail + ","  + str(bytes_received) + ","  + str(bytes_sent) + ","  +  dnsResponse  + ","  + str(t_score)  + ","  + str(c_score)  + ","  + client_name  + ","  + client_token   + ","  + keyboard_id + ",\"" + str(dst_ports) + "\",\""  + target_domains + "\"" + ",\""  + protocol_ports + "\"" + "," + str(num_attempts) + "," + str(num_successes)  + "," + app_protocol + "," + protocol  + "," + request + ",\"" + accounts + "\"" + ",\"" + shares + "\"" + "," + realm + "," + reason + "," + uuid
            f.write(strOut + "\n")
            if "dst_ips" in grouped_detail:
              if len(grouped_detail['dst_ips']) > 1:
                #print(externalTargetIP)
                if len(listExclusion) > 0:
                  if boolExcludeDest == True and externalTargetIP in listExclusion:
                    continue
                for y in range(1, len(grouped_detail['dst_ips'])):
                  strOut = hostName  + "," + src_ip  + "," +  grouped_detail['dst_ips'][y] + "," + externalTargetDomain + "," +  detection_type + "," +  first_timestmap + "," +  last_timestamp + "," + attacker_detail + ","  + str(bytes_received) + ","  + str(bytes_sent) + ","  +  dnsResponse + ","  + str(t_score)  + ","  + str(c_score)  + ","  + client_name  + ","  + client_token   + ","  + keyboard_id + ",\""  + str(dst_ports) + "\",\""  + target_domains + "\"" + ",\""  + protocol_ports + "\"" + "," + str(num_attempts) + "," + str(num_successes)  + "," + app_protocol  + "," + protocol  + "," + request + ",\"" + accounts + "\"" + ",\"" + shares + "\"" + "," + realm + "," + reason + "," + uuid
                  f.write(strOut + "\n")
  f.write("]")
