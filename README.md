# Suricata_Signature_And_Logs
##Coursera Google Cybersecurity Lab, examine logs and signature with Suricata

This is a scenario from Google's Cybersecurity course where you simulate a security analyst monitoring traffic on employer's network. Some of the tasks involved on this simulation are creating custom rules for Suricata, and examining JSON log files produced. Suricata is an open-source IDS, IPS and network analysis tool all in one used by IT and Cybersecurity professionals to monitor/guard network traffic and create custom rules or alerts. Included are the tasks for the lab, but my own custom rule which I created to test my knowledge.

### Task 1: Examining Suricata Custom Rules
![Custom Suricata Rule](https://github.com/grey-camel/Suricata_Signature_And_Logs/blob/main/customrule.png)
Introduced in the first task is our very first custom rule for Suricata. The objective is to analyze it to get familiar with the program. Each rule is broken into three components, an action, header, and rule options. In this example, alert would be the action, some other common actions on IDS programs include pass drop and reject. The next part is the header, this header defines the rule's attributes, source and destination ip, and direction. In this rule, the protocol would be http, the $HOME_NET & $EXTERNAL_NET are local shell variables defined in the Suricata .yaml file, and the arrow indicates traffic direction (from home network to external network). The rule options are settings you can configure to narrow down the traffic, and can be implemented in json key value pairs. 
This rule specifically states to alert any http traffic coming from the internal network and leaving to an external network, with the message "GET on wire", the flow:established, to_server tells it to match packets from the client to the responding device, next will look for the HTTP method in the header "GET" which is used to receive information from a server, followed by the signature ID which defines the rule and finally the rev:3 option which identifies signature version.

### Task 2: Trigger the custom rule
The next task is to get the rule to trigger to test functionality. We do this by running the suricata command in bash with the following flags, -r sample.pcap for input file to mimic traffic, -S custom.rules to instruct Suricata to use rules defined in custom.rules file, and -k none to disable checksum values. We get the following results:

![Result from running Suricata command](https://github.com/grey-camel/Suricata_Signature_And_Logs/blob/main/results.png)
The result produces logs which let us analyze our results which include a eve.json log file going into detail, and a fast.log file providing a quick summary. Here is a snippet of the JSON file 

{
  "timestamp": "2022-11-23T12:38:34.624866+0000",
  "flow_id": 622639601842325,
  "pcap_cnt": 70,
  "event_type": "alert",
  "src_ip": "redacted",
  "src_port": 49652,
  "dest_ip": "redacted",
  "dest_port": 80,
  "proto": "TCP",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 12345,
    "rev": 3,
    "signature": "GET on wire",
    "category": "",
    "severity": 3
  }clear

  ### Task 3: Custom, make my own rule

Now armed with the knowledge and functionality of Suricata, I wanted to create my own rule. Hackers will often bypass web vulnerabilites by taking advantage of the system put in place. I mentioned earlier HTTP headers include "PUT", "POST", and "DELETE" which respectively means update data, provide data, and delete data. In this rule of mine, I've set an alert to anyone using DELETE rather than GET to bypass authorization on a website being hosted.

alert http any any -> $HOME_NET any (msg:"DELETE on wire"; flow:established,to_server; content:"DELETE"; http_method; sid:42445; rev:3;)
