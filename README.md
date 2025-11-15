# How to Automate Malicious File Remediation Using GuardDuty and Systems Manager
Automated threat detection and response not only reduce the operational workload for enterprise security operators and shorten response times but also meet the requirements of security frameworks such as MLPS and PCI DSS. In Amazon Web Services' cloud adoption framework security best practices guide, security automation and response are explicitly stated as key guiding principles.

You can build your solution for automated detection and response to security threats in your cloud environment using various Amazon Web Services products. For example, you can configure Lambda functions to automatically respond to suspicious or malicious behavior detected by GuardDuty by setting up event triggers. Depending on the type of event detected, you can configure different automated response actions, including modifying network access control rules, terminating EC2 instances, or revoking IAM security credentials.

In our blog post, we describe how to use Amazon Web Services' Systems Manager product to automate the response (deletion) to malicious or virus-infected files detected by GuardDuty, meeting the technical requirements of enterprise security operations and compliance.

For automated response solutions based on GuardDuty detection findings, Amazon Web Services already provides a solution for automatic blocking of malicious IP addresses by automatically adding rules to VPC NACL and WAF ACL. Please refer to the link provided for more details. This solution focuses on automated response to malicious files detected by GuardDuty, achieving file deletion using SSM to execute shell commands. To enable customers to use both solutions simultaneously, the code (including CloudFormation and Lambda code) for this solution is based on the framework of the previous solution. Customers only need to adjust the event types they want to automate in EventBridge to achieve the desired outcome of using either solution or both simultaneously.

# Introduction to Core Cloud Services Used in the solution
* AWS GuardDuty is a threat detection service that continuously monitors your AWS account and workloads for malicious activities, providing detailed security detection results. The newly introduced Malware Protection feature within GuardDuty is designed to help you identify malicious files on EC2 or container instances without the need to deploy an agent on those instances. Instead, it achieves this through scanning Elastic Block Store (EBS) volumes. The types of malicious files it can detect include trojans, worms, cryptocurrency miners, rootkits, bots, and more.
* GuardDuty generates findings that highlight potential security issues within your environment, including affected EC2 or container workloads, compromised cloud environment credentials and so on. It is crucial to promptly address these findings by conducting a thorough review and implementing appropriate actions. This may involve investigating the presence of malicious files on impacted EC2 instances and executing manual or automated processes to remove these malicious files as deemed necessary for security mitigation.
* Systems Manager is an end-to-end cloud resource management product that encompasses AWS cloud resources as well as resources in hybrid or multi-cloud environments. The Run Command feature is a critical module within the Systems Manager. With this module, you can remotely and securely manage the configuration of EC2 instances which includes automating system administration tasks and making one-time configuration changes.

# Solution Introduction
In this blog, we will briefly explain how to automatically respond to real-time malicious file detections by GuardDuty and Systems Manager. When GuardDuty detects the presence of malicious files (Malware), it will instantly trigger a Lambda function. This Lambda function, in turn, utilizes Systems Manager to remove the identified malicious files from EC2 instances. Before deleting the files, a backup of the files and their associated information will be created in both S3 and DynamoDB, facilitating potential file recovery when needed.
The Lambda sample code is Python3.9, We will update it to Python3.11.

* The overall architecture diagram of this solution is as follows: 
![image](https://github.com/HanqingAWS/amazon-guardduty-waf-acl-ssm/blob/main/amazon-guardduty-waf-acl-ssm.jpg)
Step-by-step explanation:

1.	GuardDuty detects the discovery of a malicious file, resulting in a finding.

2.	EventBridge configures an event rule to capture GuardDuty finding results with the event type "execution:EC2/MaliciousFile."

3.	EventBridge receives GuardDuty finding results of type "execution:EC2/MaliciousFile," triggering the first Lambda function, which then parses the content of the GuardDuty finding results.

4.	Within the first Lambda function, Systems Manager's run command is used to retrieve the malicious file and its attributes on EC2. Subsequently, Systems Manager's run command is used to upload the malware file to S3 for backup purposes. The backup of the malicious file and its attributes is essential for manual recovery in case of accidental deletion.

5.	In the first Lambda function, a new item is initially created in DynamoDB to store the profile information of the malware, including EC2 instance ID, file path, file attribute information, and the item status is set to "created."

6.	The asynchronous results of the Systems Manager's run command in step 4 automatically create an execution result file in the SystemsManagerOutputPrefix directory of S3. The writing event of this file (also an EventBridge event) triggers the second Lambda.

7.	The second Lambda begins by downloading the execution result file, which contains the backup information of the malware file, from S3. If successful, it proceeds to the next step.

8.	The second Lambda updates the DynamoDB item status to "archived," indicating that the malware file has been successfully backed up on S3.

9.	Using the malware file name, it retrieves the file path and EC2 instance ID from DynamoDB. Based on the EC2 instance ID, Systems Manager's run command is used to delete the malicious file on EC2.

10.	The DynamoDB item is updated to "deleted" status, signifying the successful deletion of the malicious file on EC2.

11.	The email notification is sent via SNS to inform that the malicious file found on EC2 has been successfully removed.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
