import requests
from epochconverter import epoch_to_iso
from fileGenerator import newfileName
import json
import datetime
import lambda_function
import boto3

def upload_file_to_bucket(file_name, bucket, object_name=None):
    
    """Upload a file to an S3 bucket
    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    s3_client = boto3.client('s3')
    try:
        #response = s3_client.upload_file("/tmp/{}".format(file_name), bucket, object_name)#
        response = s3_client.upload_file(file_name, bucket, object_name)
    except Exception as e:
        print(e)
        return False
    return True

def recursive_function(api_link, first_file_name):

    devices = []
    findings = []
    canary = "Canary Tokens"
    print(f"getting {api_link}")
    r = requests.get(api_link)
    devices += r.json().get("devices",[])

    for device in devices:
        finding_data = {}
        if device.get("description"):
            finding_data['acknowledged'] = device.get("description", {}).get("acknowledged", "No acknowledged")
            finding_data['created'] = device.get("description", {}).get("created", '0')
            finding_data['created_std'] = device.get("description", {}).get("created_std", "No created_std")
            finding_data['description'] = device.get("description", {}).get("description", "No description")
            finding_data['dst_host'] = device.get("description", {}).get("dst_host", "No host")
            finding_data['dst_port'] = device.get("description", {}).get("dst_port", "No port")
            finding_data['events'] = device.get("description", {}).get("events","No events token")
            finding_data['event_count'] = device.get("description", {}).get("events_count","No event_count")
            finding_data['memo'] = device.get("description",{}).get("memo", "No memo")
            for event in finding_data['events']:
                finding_data['canarytoken'] = event.get("canarytoken","No canary token")
                finding_data['hostname'] = event.get("hostname","No hostname")
                finding_data['type'] = event.get("type","No type")
                if event.get("geoip"):
                    finding_data['continent_code'] = event.get("geoip",{}).get("continent_code","No continent")
                    finding_data['city'] = event.get("geoip",{}).get("city", "No city")
                    finding_data['country'] = event.get("geoip",{}).get("country", "No country")
                    finding_data['country_code'] = event.get("geoip",{}).get("country_code", "No country_code")
                    finding_data['country_code3'] = event.get("geoip",{}).get("country_code3", "No country_code3")
                    finding_data['hostname'] = event.get("geoip",{}).get("hostname", "No hostname")
                    finding_data['ip'] = event.get("geoip",{}).get("ip", "No ip")
                    finding_data['latitude'] = event.get("geoip",{}).get("latitude", "No latitude")
                    finding_data['longitude'] = event.get("geoip",{}).get("longitude", "No longitude")
                    finding_data['region'] = event.get("geoip",{}).get("region", "No region")
                    finding_data['valid'] = event.get("geoip",{}).get("valid", "No valid information")
                if event.get("ip_blocklist"):
                    finding_data['is_proxy'] = event.get("ip_blocklist",{}).get("is_proxy", "No proxy information")
                    finding_data['is_tor'] = event.get("ip_blocklist",{}).get("is_tor", "No tor information")
                    finding_data['is_vpn'] = event.get("ip_blocklist",{}).get("is_vpn", "No vpn information")
                if event.get("ip_blocklist"):
                    finding_data['src_host'] = event.get("src_host", "No src_host information")
        
    findings.append({
                "AwsAccountId": "77777777777", #your aws account id
                "CreatedAt": epoch_to_iso(int(finding_data["created"])),
                "Description": finding_data["description"],
                "GeneratorId": "v123-test",
                "Id": "v123-"+finding_data["created"], #unique id
                "Malware": [ 
                    { 
                        "Name": canary,
                    }
                ],
                "Network" : {
                    "SourceDomain": "canarytokens.org",
                    "SourceIpV4": finding_data['ip'],
                    "SourcePort": int(finding_data["dst_port"])
                },
                "Note": {
                    "Text": "Example text",
                    "UpdatedAt": epoch_to_iso(int(finding_data["created"])),
                    "UpdatedBy": "v123" #who updated this?
                },
                "ProductArn": "arn:aws:securityhub:us-west-7:777777777777:product/77777777777/default", #your product arn
                "ProductFields": {
                    "acknowledged": finding_data['acknowledged'],
                    "created": finding_data['created'],
                    "created_std": finding_data['created_std'],
                    "description": finding_data['description'],
                    "dst_host": finding_data['dst_host'],
                    "dst_port": finding_data['dst_port'],
                    "canarytoken": finding_data['canarytoken'],
                    "hostname": finding_data['hostname'],
                    "type": finding_data['type'],
                    "continent_code": finding_data['continent_code'],
                    "city": finding_data['city'],
                    "country": finding_data['country'],
                    "country_code": finding_data['country_code'],
                    "country_code3": finding_data['country_code3'],
                    "ip": finding_data['ip'],
                    "latitude": str(finding_data['latitude']),
                    "longitude": str(finding_data['longitude']),
                    "region": finding_data['region'],
                    "valid": str(finding_data['valid']),
                    "is_proxy": str(finding_data['is_proxy']),
                    "is_tor": str(finding_data['is_tor']),
                    "is_vpn": str(finding_data['is_vpn']),
                    "src_host": finding_data['src_host'],
                    "memo": finding_data['memo'],
                    "event_count": finding_data['event_count']
                },
                "RelatedFindings": [ 
                { 
                    "Id": "77777777777",
                    "ProductArn": "arn:aws:securityhub:us-west-7:77777777777:product/77777777777/default"#your product arn
                }
                ],
                "Resources": [
                    {
                    "Type": "Email Address",
                    "Id": "your.email@randomdomain.com",
                    "Partition": "aws",
                    "Region": "us-west-7", #your aws region
                    "Tags": {
                    "billingCode": "3343 G",
                    "needsPatching": "true"
                        },
                    }
                ], 
                "SchemaVersion": "2018-10-08",
                "Severity": { 
                    "Normalized": 1,
                    "Product": 33
                }, 
                "Title": "CANARY TOKENS CONSOLE FINDINGS",
                "Types": [ "Canary Alert" ],
                "UpdatedAt": epoch_to_iso(int(finding_data["created"]))
            })
    
    with open(first_file_name, "w") as write_file:
        json.dump(findings, write_file, indent=4)
    upload_file_to_bucket(first_file_name, 'v123-bucket', first_file_name)
    
    securityhub = boto3.client('securityhub')
    
    if len(findings) > 0:
        print("file imported")
        response = securityhub.batch_import_findings(
            Findings=findings
        )
        
    if (r.json().get("cursor",{}).get("next_link")) == None:
        print("failed", r.json().get("cursor",{}).get("next_link"))
        print(first_file_name)
    else:
        next_link = r.json().get("cursor",{}).get("next_link")
        print("worked", r.json().get("cursor",{}).get("next_link"))
        print(first_file_name)

        file_to_pass = "/tmp/"+ newfileName()
        print(file_to_pass)
        recursive_function(next_link, file_to_pass)
