import bmpy_utils as utils
from bm_runtime.standard import Standard
from bm_runtime.standard.ttypes import BmCrc32Config

# config hash function params for independent hash functions
thrift_ip = "127.0.0.1"
thrift_port_base = 9090
crc_config_value = [-205672889,223150402,1469222333,174204510,-1582538616,45132450,1679891265,876601333,1672532837,490955083,1579778662,1669898440,554310073,-898616068,-1855359410,-1985146569,1988240175,621164687,1197221587,-642605514,126591395,275461766,-2041647467,-1485850138,-774884966,-1202846761,1953853425,1099910053,1074103256,-1110092364]
for i in range(17):
    crc_config_index = 0
    thrift_port = thrift_port_base + i
    [client] = utils.thrift_connect(thrift_ip, thrift_port,[("standard", Standard.Client)])
    hash_func_base = "calc"
    for j in range(0,10):
        hash_func = hash_func_base
        if j>0:
            hash_func+="_"+str(j-1)
        config = BmCrc32Config(crc_config_value[crc_config_index],crc_config_value[crc_config_index+1],crc_config_value[crc_config_index+2],1,1)
        client.bm_set_crc32_custom_parameters(0,hash_func,config)
        crc_config_index+=3

