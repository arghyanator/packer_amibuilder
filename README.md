
# packer-amibulder
### Custom AMI Builder using packer and Chef Solo or Chef Local or Chef Zero
Create an EC2 t2.micro instance with IAM role assigned to orchestrate and build an EBS backed AMI based on custom AMIs

#### Steps to set up Packer Framework in AWS account

##### Step 1 - Create IAM Policy
IAM policy - packer_amibuilder_IAM_policy

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PackerSecurityGroupAccess",
            "Action": [
                "ec2:CreateSecurityGroup",
                "ec2:DeleteSecurityGroup",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "PackerAMIAccess",
            "Action": [
                "ec2:CreateImage",
                "ec2:CopyImage",
                "ec2:RegisterImage",
                "ec2:DeregisterImage",
                "ec2:ModifySnapshotAttribute",
                "ec2:Describe*"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "PackerSnapshotAccess",
            "Action": [
                "ec2:CreateSnapshot",
                "ec2:DeleteSnapshot"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "PackerInstanceAccess",
            "Action": [
                "ec2:RunInstances",
                "ec2:StartInstances",
                "ec2:StopInstances",
                "ec2:RebootInstances",
                "ec2:TerminateInstances",
                "ec2:CreateTags"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "PackerKeyPairAccess",
            "Action": [
                "ec2:CreateKeyPair",
                "ec2:DeleteKeyPair"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "PackerEBSAccess",
            "Action": [
                "ec2:AttachVolume",
                "ec2:CreateVolume",
                "ec2:DeleteVolume",
                "ec2:DetachVolume"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "PackerS3Access",
            "Action": [
                "s3:Get*",
                "s3:List*",
                "s3:PutObject*",
                "s3:DeleteObject*"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "PackerS3BucketAccess",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:CreateBucket"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        }
    ]
}
```

##### Step 2 - IAM Role using this policy


##### Step 3 - Create S3 bucket where we will upload all software packages to be used or installed to customize our AMI

S3 bucket - https://s3.amazonaws.com/somefolder

##### Step 4 - Create Amazon Linux based t2.micro instance and install Hashicorp Packer in it

Hashicorp Packer [downloads](https://www.packer.io/downloads.html)

Install Steps:

```
# wget -O packer_1.2.1_linux_amd64.zip https://releases.hashicorp.com/packer/1.2.1/packer_1.2.1_linux_amd64.zip?_ga=2.134145998.1560894907.1519937200-1569311150.1519937200
--2018-03-01 22:35:47--  https://releases.hashicorp.com/packer/1.2.1/packer_1.2.1_linux_amd64.zip?_ga=2.134145998.1560894907.1519937200-1569311150.1519937200
Resolving releases.hashicorp.com (releases.hashicorp.com)... 151.101.201.183, 2a04:4e42:2f::439
Connecting to releases.hashicorp.com (releases.hashicorp.com)|151.101.201.183|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18356943 (18M) [application/zip]
Saving to: ‘packer_1.2.1_linux_amd64.zip'

100%[=======================================================================================================================================================================>] 18,356,943  43.1MB/s   in 0.4s   

2018-03-01 22:35:48 (43.1 MB/s) - ‘packer_1.2.1_linux_amd64.zip’ saved [18356943/18356943]


[root@ip-10-76-151-146 ~]# unzip packer_1.2.1_linux_amd64.zip 
Archive:  packer_1.2.1_linux_amd64.zip
  inflating: packer          


[root@ip-10-76-151-146 ~]# mv packer /sbin/packer


[root@ip-10-76-151-146 ~]# packer
Usage: packer [--version] [--help] <command> [<args>]

Available commands are:
    build       build image(s) from template
    fix         fixes templates from old versions of packer
    inspect     see components of a template
    push        push a template and supporting files to a Packer build service
    validate    check that a template is valid
    version     Prints the Packer version

```

To Log in to the instance - first SSH in to the bastion_CD or dev bastion host and then from there use the 'Dev' ssh key to log in to Packer instance as 'ec2-user':
```
-bash-4.2$ ssh -i yourkey.pem ec2-user@10.x.x.x
Last login: Fri Mar  2 23:39:27 2018 from ip-10-76-151-119.ec2.internal


Version 20180302
Packer Instance
===============

No packages needed for security; 15 packages available
Run "sudo yum update" to apply all updates.
```

##### Step 5 - Create files and folders required for running packer on the packer instance

<b> AWS configs</b> 
```
# tree /root/.aws/
/root/.aws/
└── config
```

The config file looks like this (which uses the IAM instance role we created earlier)

```
[profile packerrole]
arn:aws:iam::xxxxxx:role/xxxxxpacker_amibuilder_IAM_Role
source_profile = default
```

<b> Wrapper Shell script, packer JSON file, Chef recipe and Chef client config template</b> - all under root's home folder
```
/root
├── call_packer.sh
├── ami_packer.json
├── client.rb.tpl
└── cookbooks
    └── customizami
        ├── files
        │   ├── chef_run
        │   ├── chef_terminate
        │   ├── datadog.repo
        │   └── ec2-get-credentials
        └── recipes
            └── default.rb
```

###### Wrapper Shell script:

```
#!/bin/bash
#######################
# Wrapper script that calls Hashicorp Packer to 
# build custom AMIs 
# Author: Arghya Banerjee
# Last updated: May-01-2018
#######################
set -ea

if [[ $# -ne 1 ]] ; then
    echo "No Source AMI specified...Packer quitting"
    exit 1
fi

SCRIPT_FOLDER_RELATIVE=$(dirname "$0")

if [[ -z "$COOKBOOK_PATH" ]]; then
  COOKBOOK_PATH="${SCRIPT_FOLDER_RELATIVE}/cookbooks"
fi
DATE=$(date +"%Y-%m-%d_%H_%M_%S_UTC")
TARGETAMI="PACKER_AMI_V${DATE}"
packer build -var "profile=$AWS_PROFILE" -var "SOURCEAMI=${1}" -var "TARGETAMI=${TARGETAMI}" ${SCRIPT_FOLDER_RELATIVE}/ami_packer.json

echo -e '\033[1mIf Packer Succeded above then your new AMI Name is...\033'
echo ${TARGETAMI}
echo -e '\033[1m\033[0m'
```

###### Packer JSON file:

```
{
  "_comment1": "Packer Config JSON",
  "_comment2": "Last Update Date =  2021",
  "_comment3": "Last Change = Added Version fix in install_command for chef-client provisioners",
  "_comment4": "Author = Arghya Banerjee",
  "_comment5": "Uses 'Shell' and 'chef-client' provisioners to customize AMI",
  "_comment6": "set 'knife_command' as /bin/true to trick Chef Zero server or chef-local into thinking that chef-client is always successful",
  "_comment7": "Reference = https://www.packer.io/docs/provisioners/chef-client.html",
  "variables": {
    "profile":  "{{env `AWS_PROFILE`}}",
    "packer_profile": "packer_amibuilder_IAM_Role",
    "script_folder_relative": "{{env `SCRIPT_FOLDER_RELATIVE`}}",
    "SOURCEAMI": "{{env `SOURCEAMI`}}",
    "TARGETAMI": "{{env `TARGETAMI`}}",
    "vendored_cookbooks": "{{env `SCRIPT_FOLDER_RELATIVE`}}/cookbooks/"
  },
  "builders": [{
    "type": "amazon-ebs",
    "profile": "{{user `profile`}}",
    "region": "us-east-1",
    "subnet_id": "<subnet-id>",
    "source_ami": "{{user `SOURCEAMI`}}",
    "instance_type": "t2.small",
    "ssh_username": "ec2-user",
    "security_group_ids": [ "<pre-created-secure-SG-ID>" ],
    "ami_users": ["<AWSACCOUNT1>", "<AWSACCOUNT2>"],
    "iam_instance_profile": "{{user `packer_profile`}}",
    "ami_name": "{{user `TARGETAMI`}}",
    "tags" : { "Name" : "{{user `TARGETAMI`}}" },
    "launch_block_device_mappings": [
      {
        "device_name": "/dev/xvda",
        "volume_size": 30,
        "volume_type": "gp2",
        "delete_on_termination": true
      }
    ],
    "ami_block_device_mappings": [
      {
        "delete_on_termination": true,
        "volume_type": "gp2",
        "device_name": "/dev/xvda"
      },
      {
        "device_name": "/dev/xvdk",
        "no_device": true
      },
      {
        "device_name": "/dev/xvdcz",
        "no_device": true
      }
    ]
  }],
  "provisioners" : [ 
    {
      "type": "shell",
      "inline": [
      "sudo mkdir -p /packer-chef-client/cookbooks",
        "sudo chown -R ec2-user /packer-chef-client" 
      ],
      "remote_folder": "/home/ec2-user"
    },
    {
      "type": "shell",
      "inline": ["sudo /bin/rpm -e `rpm -qa |grep chef`"],
      "remote_folder": "/home/ec2-user"
    },
    { 
      "type": "shell",
      "inline": ["aws s3 cp s3://<bucketname>/packages/chef-13.8.0-1.el7.x86_64.rpm  /packer-chef-client/chef-13.8.0-1.el7.x86_64.rpm"],
      "remote_folder": "/home/ec2-user"
    },
    {
      "type": "shell",
      "inline": ["sudo rpm -Uvh --oldpackage --replacepkgs /packer-chef-client/chef-13.8.0-1.el7.x86_64.rpm"],
      "remote_folder": "/home/ec2-user"
    },
    {
      "type": "shell",
      "inline": ["rm -f /packer-chef-client/chef-13.8.0-1.el7.x86_64.rpm"],
      "remote_folder": "/home/ec2-user"
    },
 
    {
      "type": "file",
      "source": "{{user `vendored_cookbooks`}}",
      "destination": "/packer-chef-client/cookbooks/"
    },
    {
      "type": "chef-client",
      "server_url": "http://localhost:8889",
      "install_command": "sudo /bin/rpm -e `rpm -qa |grep chef`; curl -L https://omnitruck.chef.io/chef/install.sh | {{if .Sudo}}sudo{{end}} bash -s -- -v 13.8.0",
      "config_template": "{{ user `script_folder_relative` }}/client.rb.tpl",
      "run_list": [
        "recipe[customizami]"
      ],
      "execute_command": "{{if .Sudo}}sudo {{end}}chef-client -z --audit-mode enabled --no-color -c {{.ConfigPath}} -j {{.JsonPath}}",
      "knife_command": "/bin/true",
      "staging_directory": "/packer-chef-client"
    },
    {
      "type": "shell",
      "inline": ["sudo rm -rf /packer-chef-client/ /etc/chef/*"],
      "remote_folder": "/home/ec2-user"
    },

    {
      "type": "shell",
      "inline": ["sudo /bin/rpm -e `rpm -qa |grep chef`"],
      "remote_folder": "/home/ec2-user"
    },
    {
      "type": "shell",
      "inline": ["sudo /bin/rpm -ihv /home/ec2-user/chef-11.8.2-1.el6.x86_64.rpm"],
      "remote_folder": "/home/ec2-user"
    },
    {
      "type": "shell",
      "inline": ["sudo rm -f /home/ec2-user/chef-11.8.2-1.el6.x86_64.rpm"],
      "remote_folder": "/home/ec2-user"
    }
  ]
}

```

Points to note in the JSON file:
1. "remote_folder": "/home/ec2-user" has to be specified for all shell provisioners as /tmp on custom source AMIs are not write-able by ec2-user which is what packer uses to run commands from.
2. Volume types and sizes need to be specified - custom AMIs use separate 1G volume / disk for /tmp folder

###### Chef Recipe:

```
# Cookbook used by packer
# to customize AMIs
#
###############
# Install software
# Customize AMI
###############


## Create MOTD banner
## Get current date
_time =  Time.new.strftime("%Y%m%d") 
file '/etc/update-motd.d/30-banner' do
  owner 'root'
  group 'root'
  mode '0755'
  content "
#!/bin/bash
echo \"\" 
echo \"================\"
echo \"Version #{_time}\"
echo \"================\"
"
  action :create
  notifies :run, "execute[update_motd]", :immediately
end

execute "update_motd" do
  command "MOTD=$(which update-motd) && bash ${MOTD}"
  action :nothing
end

##Create the AWS CLI Credentials directory
%w{.aws}.each do |dir|
    directory "/root/#{dir}" do
        mode '0600'
        owner 'root'
        group 'root'
        action :create
        recursive true
    end
end

# Create AWS CLI Credentials file
file '/root/.aws/config' do
  owner 'root'
  group 'root'
  mode '0644'
  content '
[profile packer]
role_arn=arn:aws:iam::<AWSACCOUNT>:role/packer_amibuilder_IAM_Role
credential_source=Ec2InstanceMetadata'
  action :create
end

## Install aws-cli utilities
package 'aws-cli' 

## Get rid of second 1G tmp volume and use root device based  /tmp folder instead
ruby_block "remove_tmp_mount" do
  block do
    %x[umount /tmp]
    %x[sed -i 's|/dev/xvdk.*$||g' /etc/fstab]
    %x[rm -rf /tmp/*]
    %x[chmod 755 /tmp]
  end
  action :create
end

## Download and Install utilities
package 'python-dateutil' 


## Install Nginx
package 'nginx'

# Install Python Dependencies to run Cloudwatch memory python script
bash "install python Dependencies for cloudwatch memory metric script" do
  code <<-EOH
    yum install -y gcc
    yum install -y python27-pip
    yum install -y python27-devel livevent-devel libevent-devel
    pip install boto psutil --user
    yum install -y python38*
    python3 -m pip install boto psutil
  EOH
  ignore_failure true
end

## Clean-up systctl-conf and tune up networking
ruby_block "clean_up_sysctl_ipv6_entries" do
    block do
        fesysctl = Chef::Util::FileEdit.new("/etc/sysctl.conf")
        fesysctl.search_file_delete_line(/^net\.ipv6.*$/)
        fesysctl.insert_line_if_no_match(/net.ipv4.ip_local_port_range=1200 65535/,
          "net.ipv4.ip_local_port_range=1200 65535")
        fesysctl.insert_line_if_no_match(/net.ipv4.tcp_tw_recycle = 1/,
          "net.ipv4.tcp_tw_recycle = 1")
        fesysctl.insert_line_if_no_match(/net.ipv4.tcp_tw_reuse = 1/,
          "net.ipv4.tcp_tw_reuse = 1")
        fesysctl.insert_line_if_no_match(/net.ipv4.tcp_window_scaling = 1/,
          "net.ipv4.tcp_window_scaling = 1")
        fesysctl.insert_line_if_no_match(/net.ipv4.tcp_max_tw_buckets = 1440000/,
          "net.ipv4.tcp_max_tw_buckets = 1440000")        
        fesysctl.write_file
    end
    action :run
end

## Increase SSHD timeout values from what Adobe ImageFactory provides
ruby_block "increase_sshd_timeouts" do
    block do
        fesshdc = Chef::Util::FileEdit.new("/etc/ssh/sshd_config")
        fesshdc.search_file_delete_line(/^ClientAliveInterval.*$/)
        fesshdc.insert_line_if_no_match(/ClientAliveInterval 86400/,
          "ClientAliveInterval 86400")       
        fesshdc.write_file
    end
    action :run
end

## Add limits.conf tuning for nfile
cookbook_file '/etc/security/limits.conf' do
  source 'limits.conf'
  owner 'root'
  group 'root'
  mode '0644'
  action :create
end

## Install NodeJS from nodesource to get latest node v10.x
execute "Set NodeJS repo to nodesource rpms" do
        command 'curl -sL https://rpm.nodesource.com/setup_14.x | bash -'
        ignore_failure true
        notifies :run, "execute[install_development_tools]", :immediately
        retries 3
end
execute "install_development_tools" do
        command 'yum groupinstall -y "Development Tools"'
        ignore_failure true
        action :nothing
        notifies :run, "execute[install_node_and_npm]", :immediately
        retries 3
end
execute "install_node_and_npm" do
        command 'yum clean all; yum -y install nodejs nodejs-devel nodejs-docs --enablerepo=nodesource'
        ignore_failure true
        action :nothing
        retries 3
end


# Add an empty crontab template with explanation of Linux Cron
file '/root/crontabfile' do
  owner 'root'
  group 'root'
  mode '0644'
  content "# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
"
  action :create
  notifies :run, "execute[update_root_crontab]", :immediately
end
execute "update_root_crontab" do
  command "crontab /root/crontabfile"
  action :nothing
  notifies :run, "execute[delete_crontabfile]", :immediately
  ignore_failure true
end
execute "delete_crontabfile" do
        command 'rm -rf /root/crontabfile'
        action :nothing
        ignore_failure true
        retries 3
end

## Finally clean all yum cache
execute "clean_yum_cache" do
        command 'yum clean all'
        ignore_failure true
        retries 3
end


```

##### Step 6 - Run a packer 'build' to build an AMI as 'root' user from /root folder on the packer instance
The whole process takes less than 10 minutes (you may check intermediate status on EC2 console as well - instance created / stopped / deleted, AMI created, etc.)
```
[root@ip-10-76-151-146 ~]# ./call_packer.sh <source-ami-id>
amazon-ebs output will be in this color.

==> amazon-ebs: Prevalidating AMI Name: AMI_V1.6
    amazon-ebs: Found Image ID: 
==> amazon-ebs: Creating temporary keypair: packer_5a99e179-87f5-ded8-8084-058024720c43
==> amazon-ebs: Creating temporary security group for this instance: packer_5a99e17e-ecb1-e206-c775-2f424fddf960
==> amazon-ebs: Authorizing access to port 22 from 0.0.0.0/0 in the temporary security group...
==> amazon-ebs: Launching a source AWS instance...
==> amazon-ebs: Adding tags to source instance
    amazon-ebs: Adding tag: "Name": "Packer Builder"
    amazon-ebs: Instance ID: i-03e9028348b06cf66
==> amazon-ebs: Waiting for instance (i-03e9028348b06cf66) to become ready...
==> amazon-ebs: Waiting for SSH to become available...
==> amazon-ebs: Connected to SSH!
....

....
==> amazon-ebs: Cleaning up chef client...
    amazon-ebs: Removing directory: /packer-chef-client
==> amazon-ebs: Provisioning with shell script: /tmp/packer-shell807607600
==> amazon-ebs: Provisioning with shell script: /tmp/packer-shell818177673
==> amazon-ebs: Provisioning with shell script: /tmp/packer-shell127895254
    amazon-ebs: warning: /home/ec2-user/chef-11.8.2-1.el6.x86_64.rpm: Header V4 DSA/SHA1 Signature, key ID 83ef826a: NOKEY
    amazon-ebs: Preparing...                          ########################################
    amazon-ebs: Updating / installing...
    amazon-ebs: chef-11.8.2-1.el6                     ########################################
    amazon-ebs: Thank you for installing Chef!
==> amazon-ebs: Provisioning with shell script: /tmp/packer-shell252538873
==> amazon-ebs: Stopping the source instance...
    amazon-ebs: Stopping instance, attempt 1
==> amazon-ebs: Waiting for the instance to stop...
==> amazon-ebs: Creating the AMI: AMI_V1.6
    amazon-ebs: AMI: ami-2469b759
==> amazon-ebs: Waiting for AMI to become ready...
==> amazon-ebs: Adding tags to AMI (ami-2469b759)...
==> amazon-ebs: Tagging snapshot: snap-02c2eb62ae28ab588
==> amazon-ebs: Creating AMI tags
    amazon-ebs: Adding tag: "Name": "AMI_V1.6"
==> amazon-ebs: Creating snapshot tags
==> amazon-ebs: Terminating the source AWS instance...
==> amazon-ebs: Cleaning up any extra volumes...
==> amazon-ebs: No volumes to clean up, skipping
==> amazon-ebs: Deleting temporary security group...
==> amazon-ebs: Deleting temporary keypair...
Build 'amazon-ebs' finished.

==> Builds finished. The artifacts of successful builds are:
--> amazon-ebs: AMIs were created:
us-east-1: ami-2469b759

```
# Python Flask API
##### Create a Python Flask wrapper API around the packer shell script
Create a python flask framework to execute the shell script with parameter remotely and secure it using AWS Security Groups and HTTPS (Nginx proxy)
```
runpacker/
├── api.py
├── db.sqlite
└── templates
    └── index.html
```
**Pyhton pip libraries required to run this Flask app and locustio testing later**
```
 pip install --upgrade pip
 pip install locustio

 pip install os
 pip install flask

 pip install flask_sqlalchemy
 pip install flask_httpauth
 pip install passlib
```

**runpacker/api.py**
```
#!/usr/bin/env python
import os
import subprocess
import time

from flask import render_template 
from flask import request
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev packer templates'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

# Create username function - Disabled - as we dont want users to be created by anyone
# @app.route('/api/users', methods=['POST'])
# def new_user():
#     username = request.json.get('username')
#     password = request.json.get('password')
#     if username is None or password is None:
#         abort(400)    # missing arguments
#     if User.query.filter_by(username=username).first() is not None:
#         abort(400)    # existing user
#     user = User(username=username)
#     user.hash_password(password)
#     db.session.add(user)
#     db.session.commit()
#     return (jsonify({'username': user.username}), 201,
#             {'Location': url_for('get_user', id=user.id, _external=True)})


# @app.route('/api/users/<int:id>')
# def get_user(id):
#     user = User.query.get(id)
#     if not user:
#         abort(400)
#     return jsonify({'username': user.username})


# Generate token by providing registered user/pass
@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/runpacker')
@auth.login_required
def runpacker():
    sourceamivar = request.args.get('sourceami', None)
    cmd = subprocess.Popen(['/root/call_packer.sh',sourceamivar],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,error = cmd.communicate()
    packerout = stdout.splitlines()

    return render_template('index.html', packerout=packerout)
 
if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
```
**runpacker/templates/index.html**
```
<html>
<body>


<h2>Packer AMI Build STDOUT</h2>
{% for line in packerout %}
    {{ line.decode('utf-8') }} </br>
   {% endfor %}

   

   
   


</body> 
</html>
```

This is started as a background process using linux **```/etc/rc.local```**:
```
#!/bin/bash
# THIS FILE IS ADDED FOR COMPATIBILITY PURPOSES
#
# It is highly advisable to create own systemd services or udev rules
# to run scripts during boot instead of using this file.
#
# In contrast to previous versions due to parallel execution during boot
# this script will NOT be run after all other services.
#
# Please note that you must run 'chmod +x /etc/rc.d/rc.local' to ensure
# that this script will be executed during boot.

touch /var/lock/subsys/local
nohup /usr/bin/python /root/runpacker/api.py >>/var/log/packerflask.log 2>&1 &
```
##### Nginx reverse proxy
Now we install nginx and use nginx as a HTTPS reverse proxy to our flask service
```
# amazon-linux-extras install nginx1.12
```
Configure nginx **```/etc/nginx/conf.d/packer.conf```**:
```
upstream packer {
    server 127.0.0.1:5000 fail_timeout=0;
}

server {
  listen 80 default;
  listen [::]:80 default;
  server_name <PublicIP>;
  return 301 https://PublicIP$request_uri;
  rewrite ^ https://PublicIP$request_uri? permanent;
}
 
server {
    listen 443 default ssl;
    server_name localhost;
    
    ssl_certificate       /etc/letsencrypt/live/localhost/fullchain.pem;
    ssl_certificate_key   /etc/letsencrypt/live/localhost/privkey.pem;

    ssl_session_timeout  5m;
    ssl_protocols  SSLv3 TLSv1;
    ssl_ciphers HIGH:!ADH:!MD5;
    ssl_prefer_server_ciphers on;
 
    location / {
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect http:// https://;
        proxy_connect_timeout       300;
        proxy_send_timeout          300;
        proxy_read_timeout          90m;
        send_timeout                300;
  
        add_header Pragma "no-cache";
 
        if (!-f $request_filename) {
            proxy_pass http://packer;
            break;
        }
    }
}
```

Create the self-signed SSL Cert and provate key in /etc/letsencrypt/live/localhost.

**Comment out all lines related to server configuration in /etc/nginx/nginx.conf (default)**

Restart nginx
```
# systemctl restart nginx.service
```

##### Run the Packer build using Python Flask API
```
curl -i "http://localhost:5000/runpacker?sourceami=ami-465fe039"
```

##### Add AWS Security Group and rule to allow access to Packer Instance
Add Security Group and rule as shown below from your data center 'Egress IP' to allow our Jenkins instance running in datacenter to access the packer Flask APIs over HTTPS.

**Don't forget to add the new Security Group to the Packer instance created earlier**

##### Jenkins "parameterized" job to call the Python Flask API and generate new AMIs on demand

##### Run Jenkins job specifying the source AMI ID

###### Files used for AMI build on dev account S3


### Test the new AMI 

- Launch a new instance from the 
- Use m4.xlarge instance size
- Use the same VPC and subnet as the dev instance
- Use this same IAM role that is being used by the DEV 
  (Currently - arn:aws:iam::xxxxxxx:instance-profile/dev-20180205215129-ec2RoleInstanceProfile-1I2PK67V7S0DM)
- Use the same Security Groups as the ones used for DEV instance
- Use this UserData script and variables:
```
#!/bin/sh
mkdir /root/.chef
mkdir /etc/chef
echo "log_level                :info
log_location             STDOUT
cache_type               'BasicFile'
cache_options( :path => '/root/.chef/checksums' )
cookbook_path [ File.expand_path('~/chef-repo/cookbooks')]
chef_server_url \"https://api.opscode.com/organizations/your-org\"
node_name \"opscode\"
client_key \"/etc/chef/opscode.pem\"
validation_client_name \"your-org-validator\"
validation_key \"/etc/chef/your-org-validator.pem\"" >/root/.chef/knife.rb
echo "-----BEGIN RSA PRIVATE KEY-----
<SAME CHEF DEV ORG VALIDATOR KEY as DEV>
-----END RSA PRIVATE KEY-----" >/etc/chef/your-org-validator.pem
noderole=tomcat
environment=dev
chefkeyloc=s3://xxxxxx/chef_keys
orgname=your-org
iamrole=True
userID=opscode
```
- Once the '/root/.chef' folder with knife.rb is created run ```/etc/init.d/chef_run start``` to test chef-client run
- If everything is working as expected following command will display tomcat/java, datadog agent running on the instance:
```
# ps -eaf |egrep "java|dd-agent" |grep -v grep
root       5254      1 24 20:29 ?        00:09:18 /usr/java/jdk1.8.0_51/bin/java -Djava.util.logging.config.file=/usr/local/apache-tomcat-7.0.53/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Xms1024m -Xmx8g -Xss256K -XX:+DisableExplicitGC -XX:+UseConcMarkSweepGC -XX:ParallelCMSThreads=2 -XX:+CMSClassUnloadingEnabled -XX:+UseCMSCompactAtFullCollection -XX:CMSInitiatingOccupancyFraction=80 -javaagent:/etc/newrelic/newrelic.jar -Dcom.sun.management.jmxremote.port=8050 -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.ssl=false -Djava.endorsed.dirs=/usr/local/apache-tomcat-7.0.53/endorsed -classpath /usr/local/apache-tomcat-7.0.53/bin/bootstrap.jar:/usr/local/apache-tomcat-7.0.53/bin/tomcat-juli.jar -Dcatalina.base=/usr/local/apache-tomcat-7.0.53 -Dcatalina.home=/usr/local/apache-tomcat-7.0.53 -Djava.io.tmpdir=/usr/local/apache-tomcat-7.0.53/temp org.apache.catalina.startup.Bootstrap start
dd-agent   6581      1  0 20:31 ?        00:00:00 /opt/datadog-agent/embedded/bin/python /opt/datadog-agent/bin/supervisord -c /etc/dd-agent/supervisor.conf
dd-agent   6586   6581  0 20:31 ?        00:00:01 /opt/datadog-agent/bin/trace-agent
dd-agent   6587   6581  0 20:31 ?        00:00:03 /opt/datadog-agent/embedded/bin/python /opt/datadog-agent/agent/ddagent.py
dd-agent   6588   6581  1 20:31 ?        00:00:35 /opt/datadog-agent/embedded/bin/python /opt/datadog-agent/agent/dogstatsd.py --use-local-forwarder
dd-agent   6589   6581  0 20:31 ?        00:00:00 /opt/datadog-agent/embedded/bin/python /opt/datadog-agent/agent/jmxfetch.py
dd-agent   6594   6581  0 20:31 ?        00:00:04 /opt/datadog-agent/embedded/bin/python /opt/datadog-agent/agent/agent.py foreground --use-local-forwarder
dd-agent   6635   6589  0 20:31 ?        00:00:16 /usr/java/jdk1.8.0_51/bin/java -Xms50m -Xmx200m -classpath /opt/datadog-agent/agent/checks/libs/jmxfetch-0.18.1-jar-with-dependencies.jar org.datadog.jmxfetch.App --check tomcat.yaml --check_period 15000 --conf_directory /etc/dd-agent/conf.d --log_level INFO --log_location /var/log/datadog/jmxfetch.log --reporter statsd:localhost:8125 --status_location /opt/datadog-agent/run/jmx_status.yaml collect
```

### Test the APP running in the new AMI based instance

- spin up an instance using the Amazon Linux LTS AMI, DEV key, in the same VPC and subnet as DEV instance, and with following user-data script (to run taurus encapsulated locustio script running 4000 clients):
```
#!/bin/bash
yum install -y python-pip
pip install locustio
yum install -y java-1.7.0-openjdk-headless.x86_64 python-devel.x86_64 libxml2-devel.x86_64 libxslt-devel.x86_64 zlib.x86_64 gcc.x86_64 gcc
pip install bzt
echo "from locust import HttpLocust, TaskSet, task
import os, json

def version(l):
    p = os.popen('date +%Y-%m-%dT%H:%M:%S.%3N%z')
    TIME = p.read()
    p.close()
    payload = {
      \"events\": [
  {
         
          }
        }
      ]
    }
    headers = {'content-type': 'application/json'}
    l.client.post(\"/someURL\", data=json.dumps(payload), headers=headers)

class UserBehavior(TaskSet):
    tasks = {version: 1}

    def on_start(self):
        version(self)

class WebsiteUser(HttpLocust):
    task_set = UserBehavior
    min_wait = 1
    max_wait = 1" >/root/locustfile.py
echo "execution:
  - executor: locust
    concurrency: 
      local: 1000
    ramp-up: 1ms
    hold-for: 30m
    think-time: 5ms
    timeout: 5ms
    scenario: 
      script: locustfile.py
      default-address: http://yourapiurl.com
reporting:
  - module: blazemeter
    report-name: locustprod
    test: locustprod
    project: locustProd" >/root/locust.yml
echo "cd /root
/usr/bin/bzt locust.yml &
/usr/bin/bzt locust.yml &
/usr/bin/bzt locust.yml &
/usr/bin/bzt locust.yml &" >/root/start_test.sh
chmod +x /root/start_test.sh
/bin/sed -i 's/rtm = int(row\["elapsed"\]) \/ 1000\.0/rtm = float(row\["elapsed"\]) \/ 1000\.0/g' /usr/local/lib/python2.7/site-packages/bzt/modules/jmeter.py
/bin/sed -i 's/ltc = int(row\["Latency"\]) \/ 1000\.0/ltc = float(row\["Latency"\]) \/ 1000\.0/g' /usr/local/lib/python2.7/site-packages/bzt/modules/jmeter.py
/bin/sed -i 's/cnn = int(row\["Connect"\]) \/ 1000\.0/cnn = float(row\["Connect"\]) \/ 1000\.0/g' /usr/local/lib/python2.7/site-packages/bzt/modules/jmeter.py
sleep 5
nohup /root/start_test.sh &
```

<b>Note:</b> Make sure to put the AMI based instance's local IP in the user-data script above to direct tests to hit the new AMI based instance

- IF everything is working as expected - instance from new AMI will send logs during load testing to splunk-us server under dev index. Search on splunk dashboard to get test results:
```
index=splunkindex  AND click-test-locustbzt4000_2
```

