# kaa

## Automation of FireEye HX
The FireEye HX system will detect malware running on computers and alert when it finds something.
What it is lacking in the current versions is the ability to automatically collect detected malware.

The **alert_manager.py** and **hx_file_downloader.py** work in tandem to provide automated acquisitions.

**alert_manager.py** will receive alerts alerts sent by the HX system and will issue a file acquisition request
**hx_file_downloader.py** will first check if the file acquisition request has completed, and if so, it will download the file

## Automation of FireEye AX
The FireEye AX is a standalone malware analysys appliance that be fed suspicios files and it will analyze them in a sandboxed environment.
**artfefact_downloader.py** will download any malware files identified by the AX system.
