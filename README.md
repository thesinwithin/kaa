# kaa

## Automation of FireEye HX
The FireEye HX system will detect malware running on computers and alert when it finds something.
What it is lacking in the current versions is the ability to automatically collect detected malware.

The **hx_alert_manager.py** and **hx_file_downloader.py** work in tandem to provide automated acquisitions.

* **hx_alert_manager.py** will receive alerts alerts sent by the HX system and will issue a file acquisition request.
* **hx_file_downloader.py** will first check if the file acquisition request has completed, and if so, it will download the file

On the HX, you must configure event logging as follows:
* HTTP per event posts
* URL http://IP.address.of.your.listener:HTTP_PORT/
* No authentication

If you want to set up an encrypted connection between the HX and the HX Alert Manager, change from http:// to https://

For the API calls to work, enable the account of the *api_analyst* username and set a password for it.

## Installation & configuration
* root directory: **/opt/kaa** with the following subfolders: **/bin**, **/etc**, **/etc/systemd**, **/etc/tls**
* systemd unit files can be found under the **etc/systemd** directory
* the digital certificate must be placed in the **/etc/tls** directory
* all the configuration options are in the **etc/config.json** and are pretty self-explanatory
