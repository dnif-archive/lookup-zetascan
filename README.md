## Zetascan   
  https://zetascan.com/

### Overview
ZetaScan rolls up critical threat feeds from leading providers, into one seamless, easy-to-integrate, high-performance API. Zetascan supports multiple API formats and creates a hardened barrier rejecting more than 90% of criminal traffic before it ever gets onto your network

##### IP address sources for Zetascan
- Spamhaus PBL
- SBL
- XBL
- CBL
- Spamhaus Real-time stream
- DNSWL IP addresses White List
- Return Path IP addresses White List
- Seclytics Black Lists

##### Domain sources for Zetascan
- Spamhaus DBL Black List
- Real-time Spamhaus ZRD (Zero Reputation Domains) list
- URIBL Black Lists
- Vade Secure Black List
- URIBL White List
- Return Path White List

##### Score calculation
ZQS provides two scoring mechanisms to grade an IP or domain-name for abuse, anti-spam measures and trustworthiness.
A negative score, like -0.1, means that an item was matched on a known trusted white-list.
If a score is 0, the item is not found within Zetascan and can be considered neutral.
A score between 0 - 1.0 is a rating on the specified domain or IP address. Scores above 0.35 should be considered as spam or fraudulent.
- Webscore
Webscore is returned by all query methods.It is used to determine a score for integrating your web-application, mobile-app or protecting your application infrastructure.
- Score
Score is also returned by all query methods, and it used to check a specified IP or domain-name for anti-spam abuse via SMTP, useful for MTA and spam-filters. This score takes into consideration email abuse, and uses a different algorithm from the 'webscore' key

Note: [For more information on scoring factor](https://zetascan.github.io/?shell#scoring-factors)
##### Lookups integrated with Zetascan

####  Retrieve Domain reports
The domain for which you want to retrieve the report
- input : a domain name.
```
_fetch $Domain from threatsample limit 1
>>_lookup zetascan get_domain_report $Domain
```

##### Sample Output 
![zs_getdomainreport](https://user-images.githubusercontent.com/37173181/38868538-fb6b8776-4264-11e8-8d31-814c880d30d2.jpg)


The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $ZSStatus      | Success or failure of the API call |
| $ZSFound | True/False if matched in a white-list/black-list. |
| $ZSItem | Queried Domain |
| $ZSLastModified | Last Modification date of the queried domain |
| $ZSScore | Score between a negative decimal number like -0.2 to 1.0 for MTA/Anti-spam abuse. |
| $ZSWebScore  | Score between a negative decimal number to 1.0 for Web/application abuse. |
| $ZSWhiteList | If the item matches a white-list.  |
| $ZSWhiteListData| White-Lists matched from ZetaScan data sources |


##### Retrieve IP address reports

The IP address for which you want to retrieve the report
- input : a valid IP address 

```
_fetch $SrcIP from threatsample limit 1
>>_lookup zetascan get_ip_report $SrcIP
```
##### Sample Output 
![zs_getipreport](https://user-images.githubusercontent.com/37173181/38868570-18d0b08e-4265-11e8-8438-5de70a8bc77e.jpg)

The Lookup call returns output in the following structure for available data  

 | Fields        | Description  |
|:------------- |:-------------|
| $ZSStatus      | Success or failure of the API call |
| $ZSFound | True/False if matched in a white-list/black-list. |
| $ZSFromSubnet | Will be true, if the IP address was found in a subnet (PBL, SBL) |
| $ZSItem | Queried IP address |
| $ZSLastModified | Last Modification date of the queried IP address |
| $ZSScore | Score between a negative decimal number like -0.2 to 1.0 for MTA/Anti-spam abuse. |
| $ZSWebScore  | Score between a negative decimal number to 1.0 for Web/application abuse. |
| $ZSWhiteList | If the item matches a white-list.  |
| $ZSWhiteListData| White-Lists matched from ZetaScan data sources |
| $ZSASN | The autonomous system number of the ISP |
| $ZSRoute | The address of the network / subnet from which the activity originated |
| $ZSCountry | The location of the above network |
| $ZSDomain | The associated domain with the IP address |
| $ZSState | Display the state |
| $ZSTime | Time in UTC |
| $ZSEmailLastDay | Contains the number of detected spam emails in the last 24 hours |


### Using the Zetascan API and DNIF  
The Zetascan API is found on github at 

  https://github.com/dnif/lookup-zetascan

#### Getting started with Zetascan API and DNIF

1. #####    Login to your Data Store, Correlator, and A10 containers.  
   [ACCESS DNIF CONTAINER VIA SSH](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)

2. #####    Move to the ‘/dnif/<Deployment-key/lookup_plugins’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/lookup-zetascan.git zetascan
```
4. #####   Move to the ‘/dnif/<Deployment-key/lookup_plugins/zetascan/’ folder path and open dnifconfig.yml configuration file     
    
   Replace the tag:<Add_your_api_key_here> with your Zetascan api key
```
lookup_plugin:
  ZETASCAN_API_KEY: <Add_your_api_key_here>

```
