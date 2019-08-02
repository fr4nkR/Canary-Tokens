
from canary_console import recursive_function
import json
from fileGenerator import newfileName

def lambda_handler(event, context):
    #enter authorization link from canary tokens console
    start_api_link = "https://yourauthlink.canary.tools/api/v1/incidents/all?auth_token=77777777777777777777777777777777" #your auth api link
    
    file_to_send = "/tmp/"+newfileName()

    recursive_function(start_api_link, file_to_send)
    
    return {
        'statusCode': 200,
        'body': json.dumps('Uploaded file to S3 Bucket')
    }
