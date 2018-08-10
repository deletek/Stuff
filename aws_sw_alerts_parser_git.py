from botocore.vendored import requests
import json
import boto3
from botocore.exceptions import ClientError, ParamValidationError

API_KEY_SW = ""
FAILED_ATTEMTS_THRESHOLD = 30


def query_SW(query, method="get", payload=None):
    header = {"Content-Type": "application/json",
              "Accept": "application/json",
              "Authorization": "ApiKey {}".format(API_KEY_SW)
              }

    url = "https://XYZ.obsrvbl.com/api/v3/" + query

    if method == "get":
        res = requests.get(url, headers=header)
    elif method == "patch":
        res = requests.patch(url, json=payload, headers=header)

    else:
        return None

    if res.status_code != 200:
        print("Failed to execute query, text: {}".format(res.status_code))
        return None

    res_json = json.loads(res.text)

    return res_json

def close_alert(id):
    payload = {
        "resolved": True,
        "merit": 8
    }
    res = query_SW("alerts/alert/{}/".format(id), method="patch", payload=payload)
    if (res):
        print("closed alert {}".format(id))
    return None

def fetch_observation(id):
    print("Fetching observation number {}".format(id))

    return query_SW("observations/all/?id={}".format(id))

def find_first_free_id(network_acl, IP):
    set_rule_ids = set()

    for entry in network_acl.entries:
        if entry["CidrBlock"] == IP:
            print ("Entry already added, we avoid duplicates")
            return None

        set_rule_ids.add(entry["RuleNumber"])

    for i in range(1000, 20000):
        if i not in set_rule_ids:
            print("First free id in network acl {} is {}".format(network_acl.id, i))
            return i

    print("Couldn't find free entry in Network ACL")
    return None


def block_address(IP, network_acl):
    # SGs is a list, but we will block only in the first group

    if not network_acl:
        print ("no network ACL, so not blocking")
        return False

    IP = "{}/32".format(IP)

    id = find_first_free_id(network_acl, IP)
    if not id:
        return False

    response = network_acl.create_entry(DryRun=False, RuleNumber=id, Protocol='-1', RuleAction='deny', Egress=False,
                                        CidrBlock=IP)

    print("Address {} has been blocked".format(IP))

    return True

def send_mail(blocked_IPs):
    topic = "New addresses have been blocked based on SW Cloud"

    text = "New Blocked IP addresses are:\n"
    text += str(blocked_IPs)

    client = boto3.client('sns')

    response = client.publish(
        TopicArn='arn:aws:sns:eu-west-1:XYZ8:SW_CLOUD_ALERTS',
        Message=text,
        Subject=topic,
    )

    print("E-mail sent")

def remote_access_excessive(event, network_acl):
    print("Parsing {} event, number of alert {}".format(event["type"], event["id"]))

    blocked_IPs = set()

    if not network_acl:
        print ("no Network ACL could be fetched, so there is nothing to block in")
        return None

    # let's go through observations
    for observation in event["observations"]:
        obs = fetch_observation(observation)

        if not obs:
            continue

        for element in obs['objects']:
            if element["failed_attempts"] > FAILED_ATTEMTS_THRESHOLD:
                ip = element["connected_ip"]
                print("More attempts than threshold, let's block the guy with IP {}".format(ip))

                blocked = block_address(ip, network_acl)

                if blocked:
                    blocked_IPs.add(element)

    if blocked_IPs:
        send_mail(blocked_IPs)

def aws_get_network_ACL(hostname):
    # based on hostname let's get Security Groop
    ec2 = boto3.resource('ec2')

    print("Getting Network ACL")

    try:
        instance = ec2.Instance(hostname)

        vpc = instance.vpc
        subnet = instance.subnet

        nacldefault = ec2.network_acls.filter(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc.id]}])

        for s in nacldefault:
            for ass in s.associations:
                if ass["SubnetId"] == subnet.id:
                    print ("Found Network ACL {} for Subnet ID {}".format(s.id, subnet.id))
                    return s

        return None

    except ClientError as e:
        # if e.response["Error"]["Code"] ==
        print (str(e))
        return None

def analyse_alert(event):
    # if type(event) is not dict:
    #    print("Input is not dict, leaving")
    #    return None

    # let's check type
    # based on type let's make an action
    print("analyse_alert() We got event")
    type = event["type"]

    print(event)

    if type == "Excessive Access Attempts (External)":
        network_acl = aws_get_network_ACL(event["hostname"])
        remote_access_excessive(event, network_acl)

    # close the alert
    close_alert(event["id"])

    return None

def lambda_handler(event, context):
    print("Lambda SW executed, parsing Records")
    for message in event["Records"]:
        analyse_alert(json.loads(message["body"]))

def test():
    analyse_alert(event)
    #close_alert(2)

#test()
