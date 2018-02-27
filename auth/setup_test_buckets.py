#!/usr/bin/env python
from __future__ import print_function
import boto3

# only used to remove InsecureRequestWarning - remove later
import botocore
botocore.vendored.requests.packages.urllib3.disable_warnings(botocore.vendored.requests.packages.urllib3.exceptions.InsecureRequestWarning)

session = boto3.session.Session()

s3_client = session.client(service_name="s3", endpoint_url="https://ceph-res-gw1.fds.rl.ac.uk", verify=False)

smudge = "/media/sf_Shared/Smudge.jpg"
other_smudge = "/media/sf_Shared/other_smudge.jpg"
not_a_cat = "/media/sf_Shared/not_a_cat.jpg"

s3_client.delete_object(Bucket="unprotected-test-bucket", Key="not_a_cat.jpg")
s3_client.delete_object(Bucket="authorised-test-bucket", Key="Smudge.jpg")
s3_client.delete_object(Bucket="unauthorised-test-bucket", Key="Smudge.jpg")
s3_client.delete_object(Bucket="authorised-test-bucket", Key="more_smudge/Other_Smudge.jpg")
s3_client.delete_object(Bucket="unauthorised-test-bucket", Key="more_smudge/Other_Smudge.jpg")
s3_client.delete_bucket(Bucket="unprotected-test-bucket")
s3_client.delete_bucket(Bucket="authorised-test-bucket")
s3_client.delete_bucket(Bucket="unauthorised-test-bucket")

s3_client.create_bucket(Bucket="unprotected-test-bucket", ACL="public-read-write")
s3_client.create_bucket(Bucket="authorised-test-bucket", ACL="public-read-write")
s3_client.create_bucket(Bucket="unauthorised-test-bucket", ACL="public-read-write")

s3_client.upload_file(not_a_cat, "unprotected-test-bucket", "not_a_cat.jpg", ExtraArgs={"ACL": "public-read-write"})

s3_client.upload_file(smudge, "authorised-test-bucket", "Smudge.jpg", ExtraArgs={"ACL": "public-read-write"})
s3_client.upload_file(other_smudge, "authorised-test-bucket", "more_smudge/Other_Smudge.jpg", ExtraArgs={"ACL": "public-read-write"})

s3_client.upload_file(smudge, "unauthorised-test-bucket", "Smudge.jpg", ExtraArgs={"ACL": "public-read-write"})
s3_client.upload_file(other_smudge, "unauthorised-test-bucket", "more_smudge/Other_Smudge.jpg", ExtraArgs={"ACL": "public-read-write"})
