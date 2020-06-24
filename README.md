# hacker101_CTF_Encrypted_Pastebin
Get 3 flags for the Hacker101 CTF problem Encrypted Pastebin

"Encrypted Pastebin" is one of the hardest problems in the Hacker101 CTF. It challenges the user to perform cryptographic attack against the data encrypted using the AES-CBC scheme. In order to get the hidden flags an user has to write scripts to automate the http requests and all the calculations.

To run the script:
```
git clone https://github.com/eggburg/hacker101_CTF_Encrypted_Pastebin.git
cd hacker101_CTF_Encrypted_Pastebin
python3 main.py 'URL_GENERATED_BY_THE_CTF_PROBLEM'
```

Below is a sample of the script output.
Note that I shielded my flags from the below output. You should be able to see yours correctly after running the script.

```
$ python3 main.py 'http://35.227.24.107/f27874c9b0/?post=4t12rIGa921awTVHfD6-Sp3!YfZS2MuTU1ocM7nX06ZG7iqGzOzstZUKzvnwFmcJfs7SJ8EEsM5SOc2BoptbOpLNp1m-UYxmm0kJMdFFhbt3ELGe!WV5hxlag0a!6fTSkIeIrqe8IDNcD5562DMiI0ph87cS7Glve9YGu6xqHrDIFjuw9vvs5QUJtI3r6-jKhqYP!J!C0UcPS-Ze8p!NGw~~'
INFO <module>:
orig_url = http://35.227.24.107/f27874c9b0/?post=4t12rIGa921awTVHfD6-Sp3!YfZS2MuTU1ocM7nX06ZG7iqGzOzstZUKzvnwFmcJfs7SJ8EEsM5SOc2BoptbOpLNp1m-UYxmm0kJMdFFhbt3ELGe!WV5hxlag0a!6fTSkIeIrqe8IDNcD5562DMiI0ph87cS7Glve9YGu6xqHrDIFjuw9vvs5QUJtI3r6-jKhqYP!J!C0UcPS-Ze8p!NGw~~
INFO get_prePT_for_block_b: Calculating for Block 9 ...
INFO get_prePT_for_block_b: Calculating for Block 8 ...
INFO get_prePT_for_block_b: Calculating for Block 7 ...
INFO get_prePT_for_block_b: Calculating for Block 6 ...
INFO get_prePT_for_block_b: Calculating for Block 5 ...
INFO get_prePT_for_block_b: Done with Block 8
INFO get_prePT_for_block_b: Calculating for Block 4 ...
INFO get_prePT_for_block_b: Done with Block 9
INFO get_prePT_for_block_b: Calculating for Block 3 ...
INFO get_prePT_for_block_b: Done with Block 5
INFO get_prePT_for_block_b: Calculating for Block 2 ...
INFO get_prePT_for_block_b: Done with Block 7
INFO get_prePT_for_block_b: Calculating for Block 1 ...
INFO get_prePT_for_block_b: Done with Block 6
INFO get_prePT_for_block_b: Done with Block 3
INFO get_prePT_for_block_b: Done with Block 4
INFO get_prePT_for_block_b: Done with Block 1
INFO get_prePT_for_block_b: Done with Block 2
INFO get_2nd_flag: flag found = ^FLAG^...........................................$FLAG$
INFO get_1st_and_3rd_flag: flags found =
INFO get_1st_and_3rd_flag: ['^FLAG^...........................................$FLAG$', '^FLAG^...........................................$FLAG$']
```
