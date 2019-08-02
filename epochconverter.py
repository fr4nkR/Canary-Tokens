import datetime
from datetime import datetime, timedelta
import time

def epoch_to_date(x): #converts epoch to human-readable time
    
    y = time.strftime('%Y %b %d %H:%M:%S', time.localtime(x))
    
    return y

def epoch_to_iso(etime): #converts epoch time to ISO 8601
    
    format = '%Y-%m-%dT%H:%M:%SZ'
    ts = datetime.fromtimestamp(etime)
    
    return ts.strftime(format)
