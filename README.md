# open-id-connect

## Deploying the IDP

### Ansible Configuration

**Requirements**

 - Ansible Host 
   - Ubuntu Server 16.04.1 or later
   - 1GB RAM
   - 1 CPU
   - 20GB Disk Space

 - IDP Host
   - Ubuntu Server 16.04.1 or later
   - 1GB RAM
   - 1 CPU
   - 20GB Disk Space

   
**Step 1**

Install Ubuntu server on a host with the following defaults:

 - Username: user1
 - Password: \<Choose a suitable password\>
 - 

 
**Step 2**

Install pre-requisites via the package manager

````
sudo apt-get install ssh python make sshpass ansible
````

**Step 3**

Pull the open-id-connect repo from git

````
git clone https://github.com/hippodigital/open-id-connect.git
````

**Step 4**

Modify the Ansible inventory file to include the IDP host

````
cd open-id-connect/idp/ansible
vim inventory/main
````

Modify the file as

````
[all]
10.211.55.10 hostname=idp-test-deploy

#new host entry
<ip address of idp host> hostname=<desired hostname>
````

**Step 5**

Register the remote hosts key

````
ssh user1@<ip address of idp host>
````

Type **yes** to accept, then press **Ctrl+C**

**Step 6**

Run the Ansible playbook against the IDP host

````
make install limit=<ip address of idp host>
````

Enter the password for user1


