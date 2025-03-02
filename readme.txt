Upon entering Kali Linux Distro there is a procedure to do in order to make this framework start. First of all, the user needs to have the local package database updated with the latest information available (that is done by
updating using the APT package management). 
As seen in the gui.py code, the user must have admin permissions and that is done by running as superuser in order to initiate the framework (what I do is start with sudo su and continue as superuser).
If the user is also running the Kali Linux OS as virtual machine, he/she will need to activate the python virtual environment (this is a self-contained directory that that contains a specific version of Python and its
associated packages) before trying to download anything in there that are externally managed by pip or apt. 
what I press is “source myenv/bin/activate” to create an isolated python environment and switch my python session to this isolated environment. But the warning is meant to avoid any potential issues where the system’s package 
manager might override or conflict with the packages in the virtual environment, so this will help not getting this kind of error and stopping the user from downloading anything externally managed. 
For example, I imported nmap from the terminal to the system while I had activated myenv. 
In some parts of the code, the user can see what is needed to be downloaded in order to start the framework, but before that, the user needs to have entered in the folder where the framework exists (by changing directories)
and then simply write in terminal where the main.py file is, “python3 main.py”.
if there is an IDE (integrated development environment) inside Kali Linux then the user can easily execute it inside the IDE and transfer the files into it.
In order to utilize the framework, the user can start with pressing the “start packet capture” button to see the packets it has captured. This will help the user in the packet analysis process to know which packet to analyze.
The user can also see the insides of the capture_traffic.csv file instead of the button to have the packets more structured. 
Before the user starts with the execution of the framework, he/she will have to produce a replicate API key. Without this key, replicate will not generate any content and the tools txt files will only include the content of 
tool’s report. With replicate though, there will be critical vulnerabilities of the device, their cvss score and ways to avoid those vulnerabilities. 
The user can decide the token number to enter each tool in that spot. The user must keep in mind that if he/she does not have the unlimited version of replicate, he/she must use wisely the token number because they are limited.
The user must also have in mind to change anything regarding the adapter and the folder to enter the files. Such details can be seen inside the code (mostly in others.py) as notes. 
