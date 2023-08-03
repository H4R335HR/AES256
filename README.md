# AES256
Two scripts to demonstrate AES 256 CBC Encryption as well as decryption

Installation
```
git clone https://github.com/H4R335HR/AES256/
cd AES256
pip install -r requirements.txt
```


Encryptor Script:

```
usage: aes256_encryptor.py [-h] [-f] input

positional arguments:
  input       Input string or filename
options:
  -h, --help  show this help message and exit
  -f, --file  Input is a filename
```


Decryptor Script:
```
usage: aes256_decryptor.py [-h] [-v]
options:
  -h, --help     show this help message and exit
  -v, --verbose  Verbose Output
```

Examples:

Encrypt & Decrypt a string
```
python aes256_encryptor.py "Hello Dolly"
python aes256_decryptor.py
```

Encrypt & Decrypt a file
```
python aes256_encryptor.py -f /etc/passwd
python aes256_decryptor.py > passwd
```
