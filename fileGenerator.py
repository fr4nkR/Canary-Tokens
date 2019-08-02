import datetime
import uuid

def newfileName(): #generates a file with a unique name

    unique_name = uuid.uuid4().hex

    file_string = ".json"

    uniquefilename = unique_name+file_string

    return uniquefilename
