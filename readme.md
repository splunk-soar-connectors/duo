[comment]: # "Auto-generated SOAR connector documentation"
# Duo

Publisher: Blackstone  
Connector Version: 1\.0\.1  
Product Vendor: Duo Security, Inc\.  
Product Name: Auth API  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 1\.2\.265  

Use Duo Auth API to authenticate actions\.

# Duo App for Phantom

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Auth API asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_host** |  required  | string | Duo Auth API endpoint\.
**ikey** |  required  | string | Duo Auth API integration key\.
**skey** |  required  | string | Duo Auth API secret key\.
**verify\_server\_cert** |  required  | boolean | Verify server certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\. This action checks the connection and configuration\.  
[authorize](#action-authorize) - Authorize an action using Duo Push  

## action: 'test connectivity'
Validate the asset configuration for connectivity\. This action checks the connection and configuration\.

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'authorize'
Authorize an action using Duo Push

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user** |  required  | User who can authorize the action\. | string |  `email` 
**info** |  optional  | URL\-encoded keys/values with additional info\. | string | 
**type** |  optional  | Shows in the Duo Mobile app notification\. | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.result | string | 