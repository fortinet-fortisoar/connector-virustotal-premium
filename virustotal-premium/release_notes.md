#### What's Fixed

- Updated the "File > VirusTotal Premium > Enrichment" pluggable enrichment playbook to remove the "tlsh", "magic", and "vhash" keys from the "field_mapping" variable defined in the last step of the playbook, i.e., the "Return Output Data" step. This update has been made as the enrichment playbook result contained unsupported characters in some file hashes. 
- Fixed the issue with "Health Check" would be successful and the connector's status would display as "Available" even when a random URL was passed as the API key. Now the "Health Check" is successful only when a valid API key is specified. 
