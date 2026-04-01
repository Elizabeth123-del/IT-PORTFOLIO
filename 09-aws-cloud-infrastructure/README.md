# Project 09 - AWS Cloud Infrastructure Deployment
### VPC | EC2 | S3 | IAM | Apache Web Server

---

## Overview

This project demonstrates deploying a real cloud environment on AWS using core infrastructure services. A custom Virtual Private Cloud was built from scratch with public and private subnets, a live EC2 web server running Apache, an S3 storage bucket with encryption and versioning, and IAM roles configured with least privilege access. All resources are deployed in the Canada Central region (ca-central-1) in compliance with Canadian data residency best practices.

---

## Technologies Used

AWS VPC was used to create a private isolated network in the cloud. EC2 t2.micro was used to run a virtual web server on the Free Tier. Apache2 was installed on the EC2 instance as the web server software. S3 was used for cloud object storage. IAM was used for identity and access management. Security Groups were configured as a virtual firewall for the EC2 instance. Ubuntu 24.04 LTS was used as the server operating system.

---

## What Was Built

**VPC**

A custom VPC was created with the CIDR block 10.0.0.0/16 in the Canada Central region. This provides a private isolated network with up to 65,000 IP addresses. DNS resolution and DNS hostnames were enabled to allow resources inside the VPC to communicate using domain names.

**Subnets**

Two subnets were created in the ca-central-1a availability zone. The public subnet uses the CIDR block 10.0.0.0/20 and hosts internet facing resources. The private subnet uses the CIDR block 10.0.128.0/20 and is reserved for internal resources that should never be directly accessible from the internet.

**Internet Gateway**

An Internet Gateway was attached to the VPC to allow traffic to flow between the public subnet and the internet. Without this no external traffic can reach resources inside the VPC.

**Route Tables**

Route tables were configured to direct traffic correctly. The public route table routes internet bound traffic through the Internet Gateway. The private route table has no internet route which keeps private subnet resources isolated from the internet.

**EC2 Instance**

A t2.micro Ubuntu 24.04 LTS instance was launched in the public subnet. An RSA key pair was created for secure SSH access. A security group was configured with two inbound rules: SSH on port 22 restricted to a specific IP address, and HTTP on port 80 open to the internet.

**Apache Web Server**

The EC2 instance was accessed via SSH from a Windows machine using PowerShell. Apache2 web server was installed and configured. Apache was enabled to start automatically on system reboot. The web server was verified as accessible from a browser using the public IP address.

**S3 Bucket**

An S3 bucket called lizzy-portfolio-bucket was created in the Canada Central region. Bucket versioning was enabled so every file change is tracked and recoverable. Default server-side encryption was enabled using SSE-S3 so all stored files are automatically encrypted at rest. Sample files were uploaded to demonstrate storage functionality.

**IAM Role**

An IAM role called lizzy-ec2-s3-readonly-role was created with the AmazonS3ReadOnlyAccess managed policy attached. This gives the EC2 instance permission to read from S3 without using hardcoded access keys or passwords. The role was attached directly to the EC2 instance following the principle of least privilege. The server can only read S3 and cannot write, delete or access any other AWS service.

---

## Security Concepts Demonstrated

Network segmentation was applied by separating internet facing and internal resources into public and private subnets. Least privilege was applied by granting the EC2 instance read only S3 access through an IAM role rather than full access. Encryption at rest was applied by enabling SSE-S3 which encrypts all S3 objects automatically. Versioning was enabled on the S3 bucket to allow recovery of any previous file version. SSH key authentication was used instead of passwords for EC2 access. Security group rules restrict SSH to a specific IP address and HTTP traffic to port 80 only. All resources were deployed in Canada Central to comply with Canadian data residency requirements.

---

## Screenshots

The following screenshots document the full deployment process.

01_vpc_created.png shows the VPC resource map including subnets, route tables and internet gateway. 02_public_subnet.png shows the public subnet details including the CIDR block and availability zone. 02_private_subnet.png shows the private subnet details confirming no public IP is auto-assigned. 03_internet_gateway.png shows the internet gateway attached to the VPC. 04_ec2_running.png shows the EC2 instance in a running state with the public IP address. 05_security_group.png shows the security group inbound rules for SSH and HTTP. 06_apache_live.png shows the Apache web server default page live in the browser. 07_s3_bucket_created.png shows the S3 bucket created in ca-central-1. 08_s3_files_uploaded.png shows sample files uploaded to the bucket. 09_s3_encryption.png shows SSE-S3 encryption enabled on the bucket. 09_s3_versioning.png shows versioning enabled on the bucket. 10_iam_role_created.png shows the IAM role with the S3 read only policy attached. 11_iam_role_attached.png shows the IAM role attached to the EC2 instance.

---

## Key Learnings

This project demonstrated how to build a production-like cloud environment from scratch. The most important security takeaway is that IAM roles should always be used instead of hardcoded access keys when granting AWS services permission to interact with each other. Hardcoded credentials are a major security risk and a common attack vector in real world environments.

Deploying all resources in the Canada Central region ensures compliance with Canadian data sovereignty requirements which is important for organizations operating under PIPEDA and provincial privacy laws.

---

## Author

Oyinkansola Elizabeth Oluwakoya
IT Systems and Network Administration | Halifax, Nova Scotia
AWS Cloud Practitioner | CompTIA Security+ (In Progress)
GitHub: Elizabeth123-del

---

