## Centralize AWS GuardDuty

Installing this Customization will enable GuardDuty in all AWS Control Tower managed accounts, with the Audit account acting as the default GuardDuty Master.

This is done by deploying a GuardDuty Enabler lambda function in the master account. It runs periodically and checks each Control Tower managed account/region to ensure that they have been invited into the master GuardDuty account and that GuardDuty is enabled. 

## Attributions

The original code for automating GuardDuty enablement in AWS accounts is present [here](https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts).  This has been extended to work with Control Tower.

## Instructions
1. Upload the gdinviter37.py.zip to an S3 bucket, note the bucket name.
1. Gather other information for deployment parameters:
    - In AWS Organizations, look on the Settings page for the Organization ID. It will be o-xxxxxxxxxx
    - In AWS Organizations, look on the Accounts page for the Audit account ID.
1. Launch a CloudFormation stack using the aws-control-tower-guardduty-inviter.template file as the source.

## License

This project is licensed under the Apache-2.0 License.

