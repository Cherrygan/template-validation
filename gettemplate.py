
#!/usr/bin python
import boto3
import json
from ruamel.yaml import YAML
import zipfile
import os
from cfn_flip import flip, to_yaml, to_json
import time

# Data Retrieval ------------------------------------------
#Get event data and artifact location
def get_paths(bucketName, artifact):
    with open('event.json') as f:
        event = json.load(f)
    bucket = event["CodePipeline.job"]["data"]["outputArtifacts"][0]["location"]["s3Location"]
    #bucketName = bucket["bucketName"]
    #artifact = bucket["objectKey"]
    #artifactPath = bucketName+"/"+artifact
    #print(artifact, bucketName)
    return artifact, bucketName

def download_artifact(artifact,bucketName):
    # Get artifact from location , were do we save this, add timestamp?
    localZip = 'localZip.zip'
    s3 = boto3.resource('s3')
    try:
        s3.Bucket(bucketName).download_file(artifact,localZip )
        #print("File being downloaded")https://github.com/Cherrygan/template-validation.git
    except Exception as e:
        if e.response['Error']['Code'] =='404':
            print('The artifact does not exist')
        else:
            raise
    return localZip

def unzip_artifact(localZip):
    # Check if artifact is there and unzip it
    artifactExt = "./buffer"
    try:
        artifact = zipfile.ZipFile(localZip, 'r')
        artifact.extractall(artifactExt)
        artifact.close()
    except Exception as e:
        print("No zip file")
    return artifactExt

def getContent(filePath):
    with open(filePath,'r') as file:
        data = file.read()
        return data

def get_template_object(path):
    # Get content of yaml file
    file = open(path).read()
    yaml = YAML(pure=True)
    code = yaml.load(file)
    yaml.default_flow_style = False
    with open('buffer.yaml','w+') as output:
        yaml.dump(code,output) #sys.stdout

    # Convert Yaml -> JSON
    templateY = open('buffer.yaml','r').read()
    templateJ = to_json(templateY)
    #print(templateJ, type(templateJ))

    # Get template object
    object = json.loads(templateJ)
    return object

def get_all_templates(artifact):
    #print(artifact) # Where we saved the files
    allTemplateObjects=[]
    yaml = YAML(typ='safe')
    yaml.default_flow_style = False

    # Go through directory tree to find the template files
    for root, dirs, files in os.walk(artifact):
        #print(dirs, type(dirs))
        for file in files:
            if file.endswith(('.yaml', '.json')):
                fileName = os.path.join(root, file)
                #print(fileName,root)
                allTemplateObjects.append(get_template_object(fileName))
                #print(len(allTemplateObjects))
            else:
                pass
    return allTemplateObjects

# Tests Definition ----------------------------------------

'''
class ValidationTest:
    def __init__(self, testName):
        self.name = testName
        self.status = 'N/A'
        self.tested = False
    # define testing method
    # define reporting method
    # define notific

'''
def is_resource_here(template,resourceType):
    # If any, it returns the list of resources of type resourceType
    result = []
    found = False
    if "Resources" in template:
        for item in template['Resources']:
            if template['Resources'][item]['Type']:
                if template['Resources'][item]['Type'] == resourceType:
                    found = True
                    result.append(item)
                else:
                    pass
    return found,result


def test_kms_key_rotation(template): 
    searchRes = is_resource_here(template, 'AWS::KMS::Key')
    status = True
    if searchRes[0]:
        for item in searchRes[1]:
            if template['Resources'][item]['Properties']['EnableKeyRotation'] ==True:
                print(item, "is compliant with KMS-002")
                status = True
            else:
                print(item, "is NOT compliant with KMS-002 !!! ")
                status = False
    else:
        pass
    return status

def test_bucket_encryption(template):
    searchRes = is_resource_here(template, 'AWS::S3::Bucket')
    status = True
    if searchRes[0]:
        for item in searchRes[1]:
            if 'BucketEncryption' in template['Resources'][item]['Properties']:
                print(item, "is compliant with S3-011")
            else:
                print(item, "is NOT compliant with S3-011 !!! ")
                status = False
    return status

# Tests if lambda is included in a VPC. Extend with checking VPC creation(?)
def test_lambda_in_vpc(template):
    searchRes = is_resource_here(template, 'AWS::Lambda::Function')
    status = True
    if searchRes[0]:
        print(searchRes[1])
        for item in searchRes[1]:
            if 'VpcConfig' in template['Resources'][item]['Properties']:
                print(item, "is compliant with  LAM-004")
            else:
                print(item, "is NOT compliant with LAM-004 !!! ")
                status = False
    return status

def is_private(ipaddress):
    privateIps = ['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','240.0.0.0/4','255.255.255.255/32','224.0.0.0/4']
    if ipaddress in privateIps:
        print('yes')
    return True

def test_lambda_secgroup_closed(template):
    searchRes = is_resource_here(template,"AWS::Lambda::Function")
    status = True
    print(searchRes)
    if searchRes[0]:
        for item in searchRes[1]:
            if 'VpcConfig' in template['Resources'][item]['Properties']:
                lambdaVpc = True
            else:
                lambdaVpc = False
    
            if lambdaVpc:
                lambdaRes = is_resource_here(template,"AWS::EC2::VPC")
                if searchRes[0]:
                    for step in lambdaRes[1]: 
                        if is_private(template['Resources'][step]['Properties']['CidrBlock']):
                            print('Lambda Security Group ',item,'compliant with LAM-005 ')
                            status = True
                        else:
                            print('Lambda Security Group for ',item,' NOT compliant with LAM-005  !!!')
                        status = False

            else:
                print("No VPC associated, Lambda Security Group NOT compliant with LAM-005 !!!")
                status = False
    return status

def run_conformity_tests(templateSet):
    for template in templateSet:
        #test_kms_key_rotation(template)
        #test_bucket_encryption(template)
        #test_lambda_in_vpc(template)
        test_lambda_secgroup_closed(template)
        #test_sns_endpoint_encryption(template)
        #test_permissions_cbsp(template)


# Run, Forest, run!----------------------------------------
def lambda_handler(event,context):
    bucketName = "cherrygan-access"
    artifact =  "cloudformation.zip"

    path = get_paths(bucketName,artifact)
    artifact = unzip_artifact(download_artifact(path[0], path[1]))
    templateContent = get_all_templates(artifact)
    run_conformity_tests(templateContent)


if __name__ == '__main__':
    lambda_handler({'invokingEvent': '{"messageType":"ScheduledNotification"}'}, None)

