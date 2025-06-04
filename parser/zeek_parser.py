import pandas as pd

def parse_connlog(file_path):
    df = pd.read_csv(file_path, sep='\t', comment='#', header=None)
    df.columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                  'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
                  'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history',
                  'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents']
    df['ts'] = pd.to_datetime(df['ts'], unit='s')
    return df[['ts', 'id.orig_h', 'id.resp_h', 'proto']]
