## Run executable files blacklisted by Bitdefender Total Security<br>
### Usage:<br>
#### First, encrypt the executable with<br>
encrypt -i INPUT_FILE_PATH -o OUTPUT_FILE_PATH -k OUTPUT_KEY_FILE_PATH<br>
#### Now you can run the encrypted image with<br>
run -c INPUT_ENCRYPTED_FILE -k KEY_FILE_PATH -args \"ARGUMENT_LIST\"<br>
<br>
### Version Information:<br>
![image](https://github.com/user-attachments/assets/c2261b32-9dc1-4754-8416-b1d103063f5e)
<br>
### Practical Example: Running the Monero Miner (xmrig.exe)<br>
#### When trying to start the miner normally, the file will first be locked and then quarantined.<br>
![image](https://github.com/user-attachments/assets/1e80ca15-1e95-4122-a3c5-d91ba823f853)<br>
#### When starting the miner with this tool, the application will start up successfully<br>
!<br>
It does recognize the crypto mining connection, but it should never have allowed the application to start up in the first place (it is likely possible to bypass this detection as well somehow).<br>
The purpose of this demonstration was to show that a blacklisted file can be executed.
