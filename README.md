# ISO Certificate Manager
The ISO Certificate Manager is a configurable python script that searches your local Windows Certificate Stores for any certificates that would grant access to any of the North American ISOs.    


## Parameters
-m  market_code  
    Any of the following market codes should be configured in the config.yaml file  
    OATI, MISO, SPP, PJM, ERCOT, NYISO, ISONE, webCARES and CAISO  

-c  config_file  
    path to a .yaml config file specifying filters to help identify certificates.  

-v/-q will increase or decrease the logging level.  

## YAML Config File

Use the template to build your own filters for markets.  

stores - the certificate stores to search.  (Most will be found in 'MY')
filters  
&nbsp;&nbsp;market  
&nbsp;&nbsp;&nbsp;&nbsp;field  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- list of regexs  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- that will identify  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- certificates for the market  
