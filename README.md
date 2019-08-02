# Upload your own/company Canary Tokens alerts to Security Hub

# What Are Canary Tokens?

Canary tokens are a quick, painless way to help defenders discover they've been breached (by having attackers announce themselves).

# How can I get my token?

Visit your Canary Tokens console and create your own token, there are plenty of option to choose from, word documents, pdf's, AWS Keys, DNS, etc. All of these appear to be legit, but they're just tokens. Everytime someone triggers your canary (they way they are triggered depends on your token type) you will get all the necessary details to determine the attacker's info or if it is just a false positive on the console and on security hub (after deploying this repo). Additionaly, you get one file format options to download your canary's data: .json this is what this lambda function sends to security hub when the token is triggered.

## How to deploy this repo into Lambda

1 - Make sure you have all the correct modules intalled in your package as specified in requirements.txt. Download all the files and upload them to lambda as a .zip folder. Also, make sure to use a lambda layer for boto 3.19. The default boto3 provided by lambda won't work with this repo. This demo version is meant to run everytime the Canary Tokens portal sends a POST request to the canary-tokens-webhook API Gateway.

2 - One you can edit the code inline or on your prefered editor, you need to specifiy the authentication link provided under the Canary Tokens portal (settings).

5 - Also, change all the information under the json part that will be sent to Security Hub and stored in your S3 Bucket to whatever you desire. You can find more information on the requirements on https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html.

6 - You have to specify the S3 bucket where you want to keep your .json files if you wish so. It will use a unique file format so your file's name don't repeat. If you don't want to save any .json files into your S3 buckets simply comment out the lines where this is specified.

6 - That is it! If you carefully followed all the steps your lambda function will import your triggered token information and who triggered directly into Security Hub and this will forward it to Splunk.
