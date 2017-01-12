# open-id-connect

## Setup

The IDP is deployed via Ansible.  Ansible can be deployed on the IDP itself and used to configure the host locally.

### Initial Deployment

**Requirements**

 - IDP Host
   - Ubuntu Server 16.04.1 or later
   - 1GB RAM
   - 1 CPU
   - 20GB Disk Space

   
**Step 1**

Install Ubuntu server on a host with the following defaults:

 - Username: user1
 - Password: \<Choose a suitable password\>

 
**Step 2**

Install pre-requisites via the package manager

````
sudo apt-get install software-properties-common
sudo apt-add-repository ppa:ansible/ansible
sudo apt-get update
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
````

**Step 5**

Register the remote hosts key

````
ssh user1@127.0.0.1
````

Type **yes** to accept, then press **Ctrl+C**

**Step 6**

Run the Ansible playbook against the IDP host

````
make install limit=127.0.0.1
````

Enter the password for user1.

Ansible will deploy the IDP in its default configuration.


### Configuration


#### IDP Settings

Add SDH specific configuration to the IDP

````
sudo vim /etc/idp/config.yml

# Make changes to reflect the local envionment configuration

---
issuer:
    address: https://oidc.shdc.nhs.uk

idstore:
    address: 10.181.28.96
    port: 389
    serviceaccountdn: 'uid=sdhidpuser,cn=users,dc=sdhc,dc=xsdhis,dc=nhs,dc=uk'
    serviceaccountpassword: <password as set on account>
    basesearchdn: 'ou=Users,ou=SDHIS,dc=sdhc,dc=xsdhis,dc=nhs,dc=uk'

sessionstore:
    address: localhost
    port: 6379
````

Add client details for Totara LMS

````
sudo vim /etc/idp/clients.yml

# Make changes to reflect the local envionment configuration

---
clients:
    # Hashes must be lower case
    totara-lms-1: ...

````

**Step 8**

Add the SDH specific configuration to NGINX

````
sudo vim /etc/nginx/sites-available/hippo-idp

# Make changes to reflect the service FQDN and certificate locations

server {
    listen 443;
    server_name oidc.shdc.nhs.uk;

    ssl on;
    ssl_certificate /etc/idp/oidc.shdc.nhs.uk.pem;
    ssl_certificate_key /etc/idp/oidc.shdc.nhs.uk.key;

    location / {
        include uwsgi_params;
        uwsgi_pass unix:/var/idp/hippo-idp.sock;
    }
}
````


**Step 9**

Add SSL Key and Certificate to the IDP

Copy the .key and .pem files to /etc/idp as

* oidc.sdhc.nhs.uk.key
* oidc.sdhc.nhs.uk.pem





