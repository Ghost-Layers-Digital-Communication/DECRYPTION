go to your desktop or folder containing the decryption.py script

create a text file for encryption

encrypt it by running this command.

python decryption.py --create --in ONION.txt --out sample.enc --key 0x5A

to decrypt it run this command.

python decryption.py --crack --in sample.enc --top 8


this will display the message.
