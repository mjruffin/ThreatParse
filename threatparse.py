import xml.etree.ElementTree as eT
import os
import re
import csv
import platform
import argparse


# Define global variables
start_dir = ''
excluded_threats = ''
endpoint = ''
xml_path = ''
trt_root = ''


# Define the file names for the output
FileNames = {
    'filehit': os.sep + 'filehit.csv',
    'reghit': os.sep + 'reghit.csv',
    'eventhit': os.sep + 'eventhit.csv',
    'urlhit': os.sep + 'urlhit.csv',
    'prochit': os.sep + 'prochit.csv',
    'truncatedhit': os.sep + 'truncatedhit.csv',
    'moduleerror': os.sep + 'err.csv',
    'exception': os.sep + 'exception.txt',
}

# Tracks the hit counts per item
HitCounts = {
    'file': 0,
    'warning': 0,
    'event': 0,
    'reg': 0,
    'url': 0,
    'truncated': 0,
    'proc': 0,
}


def parseargs():
    parser = argparse.ArgumentParser()
    parser.add_argument("folder",
                        help="File path containing the job results.")
    parser.add_argument("-e", "--exclude_threats", nargs='+',
                        help="Exclude threats by ID. Ex: -e 24 576 255")

    args = parser.parse_args()

    # Set start folder
    global start_dir
    start_dir = args.folder

    global excluded_threats
    excluded_threats = args.exclude_threats

    # Cleanup old files
    OutputData.rename_existing_files()
    # Start the main parser
    ParseThreats.read_folder()


class ModelData:
    FileItemHit = {
        'Name': '',
        'Path': '',
        'MD5': '',
        'Extension': '',
        'Size': '',
        'Accessed': '',
        'Created': '',
        'Modified': '',
        'XML': '',
        'Endpoint': '',
    }

    RegItemHit = {
        'Hive': '',
        'Path': '',
        'Type': '',
        'ValueName': '',
        'Text': '',
        'XML': '',
        'Endpoint': '',
    }

    EventItemHit = {
        'Computer': '',
        'SourceLog': '',
        'Source': '',
        'EventID': '',
        'User': '',
        'GenerationTime': '',
        'WriteTime': '',
        'PID': '',
        'ThreadID': '',
        'CategoryNumber': '',
        'RecordID': '',
        'Message': '',
        'XML': '',
        'Endpoint': '',
    }

    ModuleErrorItemHit = {
        'Error': '',
        'XML': '',
        'Endpoint': '',
    }

    UrlItemHit = {
        'Browser': '',
        'First_Visit': '',
        'IsHidden': '',
        'Host': '',
        'Last_Visit': '',
        'Last_Visit_Local': '',
        'Profile': '',
        'Typed': '',
        'URL': '',
        'Username': '',
        'Visit_Count': '',
        'Visit_From': '',
        'Visit_Type': '',
        'XML': '',
        'Endpoint': '',
    }

    TruncatedItem = {
        'Count': '',
        'XML': '',
        'Endpoint': '',
    }

    ProcessItem = {
        'Name': '',
        'Path': '',
        'StartTime': '',
        'WorkingDir': '',
        'CommandLine': '',
        'Subsystem': '',
        'Imagebase': '',
        'PID': '',
        'ParentPID': '',
        'User': '',
        'Size': '',
        'EProcBlockLoc': '',
        'WindowTitle': '',
        'SecurityID': '',
        'SecurityType': '',
    }


class OutputData:
    @staticmethod
    def out_file_hit(filehititem, createonly):
        global start_dir
        global FileNames
        # Define the field names, must match the ThreatParse.FileHitItem model
        # The columns can be put in a new order by moving them around.
        fieldnames = ['XML', 'Endpoint', 'Name', 'Path', 'MD5', 'Extension', 'Size', 'Accessed',
                      'Created', 'Modified']

        if createonly:
            with open(start_dir + FileNames['filehit'], 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
        else:
            with open(start_dir + FileNames['filehit'], 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow(filehititem)

    @staticmethod
    def out_reg_hit(reghititem, createonly):
        global start_dir
        global FileNames
        # Define the field names, must match the ThreatParse.FileHitItem model
        # The columns can be put in a new order by moving them around.
        fieldnames = ['XML', 'Endpoint', 'Hive', 'Path', 'Type', 'ValueName', 'Text']

        if createonly:
            with open(start_dir + FileNames['reghit'], 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
        else:
            with open(start_dir + FileNames['reghit'], 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow(reghititem)

    @staticmethod
    def out_proc_hit(prochititem, createonly):
        global start_dir
        global FileNames
        # Define the field names, must match the ThreatParse.FileHitItem model
        # The columns can be put in a new order by moving them around.
        fieldnames = ['XML', 'Endpoint', 'Name', 'Path', 'CommandLine', 'WorkingDir', 'WindowTitle', 'Size', 'PID',
                      'ParentPID', 'User', 'StartTime', 'SecurityType', 'SecurityID', 'Subsystem', 'Imagebase',
                      'EProcBlockLoc']

        if createonly:
            with open(start_dir + FileNames['prochit'], 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
        else:
            with open(start_dir + FileNames['prochit'], 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow(prochititem)

    @staticmethod
    def out_url_hit(urlhititem, createonly):
        global start_dir
        global FileNames
        # Define the field names, must match the ThreatParse.FileHitItem model
        # The columns can be put in a new order by moving them around.
        fieldnames = ['XML', 'Endpoint', 'Username', 'Browser', 'IsHidden', 'Visit_Count', 'Host', 'URL',
                      'First_Visit', 'Last_Visit', 'Last_Visit_Local', 'Visit_From', 'Visit_Type', 'Profile',
                      'Typed']

        if createonly:
            with open(start_dir + FileNames['urlhit'], 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
        else:
            with open(start_dir + FileNames['urlhit'], 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow(urlhititem)

    @staticmethod
    def out_truncated_hit(truncateditem, createonly):
        global start_dir
        global FileNames
        # Define the field names, must match the ThreatParse.FileHitItem model
        # The columns can be put in a new order by moving them around.
        fieldnames = ['XML', 'Endpoint', 'Count']

        if createonly:
            with open(start_dir + FileNames['truncatedhit'], 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
        else:
            with open(start_dir + FileNames['truncatedhit'], 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow(truncateditem)

    @staticmethod
    def out_event_hit(eventhititem, createonly):
        global start_dir
        global FileNames
        # Define the field names, must match the ThreatParse.FileHitItem model
        # The columns can be put in a new order by moving them around.
        fieldnames = ['XML', 'Endpoint', 'Computer', 'SourceLog', 'Source', 'EventID', 'User', 'GenerationTime',
                      'WriteTime', 'PID', 'ThreadID', 'CategoryNumber', 'RecordID', 'Message']

        if createonly:
            with open(start_dir + FileNames['eventhit'], 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
        else:
            with open(start_dir + FileNames['eventhit'], 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow(eventhititem)

    @staticmethod
    def out_err(moduleerroritem, createonly):
        global start_dir
        global FileNames
        # Define the field names, must match the ThreatParse.FileHitItem model
        # The columns can be put in a new order by moving them around.
        fieldnames = ['XML', 'Endpoint', 'Error']

        if createonly:
            with open(start_dir + FileNames['moduleerror'], 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
        else:
            with open(start_dir + FileNames['moduleerror'], 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow(moduleerroritem)

    @staticmethod
    def create_prev_folder():
        global start_dir
        previtem = 0
        if os.path.isdir(start_dir + os.sep + 'ThreatParse_' + str(previtem)):
            while os.path.isdir(start_dir + os.sep + 'ThreatParse_' + str(previtem)):
                previtem += 1

        try:
            os.mkdir(start_dir + os.sep + 'ThreatParse_' + str(previtem))
        except os.error as e:
            print(e)

        return previtem

    @staticmethod
    def move_file(folderid, name):
        global FileNames
        global start_dir
        try:
            os.rename(start_dir + FileNames[name], start_dir + os.sep + 'ThreatParse_' + str(folderid)
                      + FileNames[name])
        except os.error as e:
            print(e)

    @staticmethod
    def rename_existing_files():
        global start_dir
        global FileNames
        foldid = 0
        mvlist = {
            'filehit': 0,
            'truncatedhit': 0,
            'prochit': 0,
            'reghit': 0,
            'eventhit': 0,
            'urlhit': 0,
            'moduleerror': 0,
            'exception': 0,
        }
        # Move previous files if ThreatParseer was ran before.
        if os.path.isfile(start_dir + FileNames['filehit']):
            mvlist['filehit'] = 1

        if os.path.isfile(start_dir + FileNames['truncatedhit']):
            mvlist['truncatedhit'] = 1

        if os.path.isfile(start_dir + FileNames['prochit']):
            mvlist['prochit'] = 1

        if os.path.isfile(start_dir + FileNames['reghit']):
            mvlist['reghit'] = 1

        if os.path.isfile(start_dir + FileNames['eventhit']):
            mvlist['eventhit'] = 1

        if os.path.isfile(start_dir + FileNames['urlhit']):
            mvlist['urlhit'] = 1

        if os.path.isfile(start_dir + FileNames['moduleerror']):
            mvlist['moduleerror'] = 1

        if os.path.isfile(start_dir + FileNames['exception']):
            mvlist['exception'] = 1

        # Move the items in the list
        if 1 in mvlist.values():
            foldid = OutputData.create_prev_folder()

        for file in mvlist:
            if mvlist[file] == 1:
                OutputData.move_file(foldid, file)

    @staticmethod
    def creation_date(path_to_file):
        """
        Try to get the date that a file was created, falling back to when it was
        last modified if that isn't possible.
        See http://stackoverflow.com/a/39501288/1709587 for explanation.
        """
        if platform.system() == 'Windows':
            return os.path.getctime(path_to_file)
        else:
            stat = os.stat(path_to_file)
            try:
                return stat.st_birthtime
            except AttributeError:
                # We're probably on Linux. No easy way to get creation dates here,
                # so we'll settle for when its content was last modified.
                return stat.st_mtime


class ParseThreats:
    @staticmethod
    def read_folder():
        global start_dir
        global excluded_threats
        global xml_path
        global endpoint
        global HitCounts
        # Iterate folder for threat.xml files
        try:
            for root, dirs, files in os.walk(start_dir):
                for name in dirs:
                    if name.startswith('Item_'):
                        # Split the endpoint name from the folder structure
                        endpoint = re.split('(Item_)(\w+|\d+)(.*)', name)[2]

                        for subroot, subdirs, subfiles in os.walk(os.path.join(root, name, '1')):
                            # Iterate all threat.xml files in the 1 folder
                            for threat in subfiles:
                                if threat is not None:
                                    # Get the ID from the threat.xml name
                                    threatid = re.match('(threat)(\d+)(.*)', threat)
                                    if threatid:
                                        threatidnmb = threatid.group(2)
                                        if excluded_threats:
                                            # If the exclude list exists, exclude the specified
                                            if threatidnmb not in excluded_threats:
                                                print(endpoint, threat)
                                                xml_path = os.path.join(subroot, threat)
                                                ParseThreats.parse_threat()
                                        else:
                                            print(endpoint, threat)
                                            xml_path = os.path.join(subroot, threat)
                                            ParseThreats.parse_threat()

            print(HitCounts)
        except os.error as ose:
            print(ose)
            with open(start_dir + FileNames['exception'], 'a') as outFile:
                outFile.write('Error reading folder. {0}\n'.format(ose))

    @staticmethod
    def hit_file():
        global start_dir
        global endpoint
        global xml_path
        global trt_root
        # FileHit
        for result in trt_root.iter('fileresult'):
            fitem = ModelData.FileItemHit
            fitem['XML'] = os.path.basename(xml_path)
            fitem['Endpoint'] = endpoint
            fitem['Name'] = ''
            if not (result.find('name')) is None:
                fitem['Name'] = (result.find('name')).text
            fitem['Path'] = ''
            if not (result.find('fullpath')) is None:
                fitem['Path'] = (result.find('fullpath')).text
            fitem['MD5'] = ''
            if not (result.find('md5')) is None:
                fitem['MD5'] = (result.find('md5')).text
            fitem['Accessed'] = ''
            if not (result.find('dateaccessed')) is None:
                fitem['Accessed'] = (result.find('dateaccessed')).text
            fitem['Created'] = ''
            if not (result.find('datecreated')) is None:
                fitem['Created'] = (result.find('datecreated')).text
            fitem['Modified'] = ''
            if not (result.find('datemodified')) is None:
                fitem['Modified'] = (result.find('datemodified')).text
            fitem['Extension'] = ''
            if not (result.find('datecreated')) is None:
                fitem['Extension'] = (result.find('extension')).text
            fitem['Size'] = ''
            if not (result.find('filesize')) is None:
                fitem['Size'] = (result.find('filesize')).text

            OutputData.out_file_hit(fitem, False)

    @staticmethod
    def hit_proc():
        global start_dir
        global endpoint
        global xml_path
        global trt_root
        # ProcHit
        for result in trt_root.iter('Process'):
            fitem = ModelData.ProcessItem
            fitem['XML'] = os.path.basename(xml_path)
            fitem['Endpoint'] = endpoint
            fitem['Name'] = ''
            if not (result.find('Name')) is None:
                fitem['Name'] = (result.find('Name')).text
            fitem['Path'] = ''
            if not (result.find('Path')) is None:
                fitem['Path'] = (result.find('Path')).text
            fitem['StartTime'] = ''
            if not (result.find('StartTime')) is None:
                fitem['StartTime'] = (result.find('StartTime')).text
            fitem['WorkingDir'] = ''
            if not (result.find('WorkingDir')) is None:
                fitem['WorkingDir'] = (result.find('WorkingDir')).text
            fitem['CommandLine'] = ''
            if not (result.find('CommandLine')) is None:
                fitem['CommandLine'] = (result.find('CommandLine')).text
            fitem['Subsystem'] = ''
            if not (result.find('Subsystem')) is None:
                fitem['Subsystem'] = (result.find('Subsystem')).text
            fitem['Imagebase'] = ''
            if not (result.find('Imagebase')) is None:
                fitem['Imagebase'] = (result.find('Imagebase')).text
            fitem['PID'] = ''
            if not (result.find('PID')) is None:
                fitem['PID'] = (result.find('PID')).text
            fitem['ParentPID'] = ''
            if not (result.find('ParentPID')) is None:
                fitem['ParentPID'] = (result.find('ParentPID')).text
            fitem['User'] = ''
            if not (result.find('User')) is None:
                fitem['User'] = (result.find('User')).text
            fitem['Size'] = ''
            if not (result.find('Size')) is None:
                fitem['Size'] = (result.find('Size')).text
            fitem['EProcBlockLoc'] = ''
            if not (result.find('EProcBlockLoc')) is None:
                fitem['EProcBlockLoc'] = (result.find('EProcBlockLoc')).text
            fitem['WindowTitle'] = ''
            if not (result.find('WindowTitle')) is None:
                fitem['WindowTitle'] = (result.find('WindowTitle')).text
            fitem['SecurityID'] = ''
            if not (result.find('SecurityID')) is None:
                fitem['SecurityID'] = (result.find('SecurityID')).text
            fitem['SecurityType'] = ''
            if not (result.find('SecurityType')) is None:
                fitem['SecurityType'] = (result.find('SecurityType')).text
            OutputData.out_proc_hit(fitem, False)

    @staticmethod
    def hit_reg():
        global start_dir
        global endpoint
        global xml_path
        global trt_root
        # RegHit
        for result in trt_root.iter('registryitem'):
            ritem = ModelData.RegItemHit
            ritem['XML'] = os.path.basename(xml_path)
            ritem['Endpoint'] = endpoint
            ritem['Path'] = ''
            if not (result.find('path')) is None:
                ritem['Path'] = (result.find('path')).text
            ritem['Hive'] = ''
            if not (result.find('hive')) is None:
                ritem['Hive'] = (result.find('hive')).text
            ritem['Type'] = ''
            if not (result.find('type')) is None:
                ritem['Type'] = (result.find('type')).text
            ritem['ValueName'] = ''
            if not (result.find('valuename')) is None:
                ritem['ValueName'] = (result.find('valuename')).text
            ritem['Text'] = ''
            if not (result.find('text')) is None:
                ritem['Text'] = (result.find('text')).text
            OutputData.out_reg_hit(ritem, False)

    @staticmethod
    def hit_truncated():
        global start_dir
        global endpoint
        global xml_path
        global trt_root
        # Truncated hit
        for result in trt_root.iter('truncateresult'):
            ritem = ModelData.TruncatedItem
            ritem['XML'] = os.path.basename(xml_path)
            ritem['Endpoint'] = endpoint
            ritem['Count'] = ''
            if not (result.find('totalcount')) is None:
                ritem['Count'] = (result.find('totalcount')).text
            OutputData.out_truncated_hit(ritem, False)

    @staticmethod
    def hit_url():
        global start_dir
        global endpoint
        global xml_path
        global trt_root
        # URLHit
        for result in trt_root.iter('urlhistoryitem'):
            ritem = ModelData.UrlItemHit
            ritem['XML'] = os.path.basename(xml_path)
            ritem['Endpoint'] = endpoint
            ritem['Browser'] = ''
            if not (result.find('browsername')) is None:
                ritem['Browser'] = (result.find('browsername')).text
            ritem['First_Visit'] = ''
            if not (result.find('firstvisitdate')) is None:
                ritem['First_Visit'] = (result.find('firstvisitdate')).text
            ritem['IsHidden'] = ''
            if not (result.find('hidden')) is None:
                ritem['IsHidden'] = (result.find('hidden')).text
            ritem['Host'] = ''
            if not (result.find('hostname')) is None:
                ritem['Host'] = (result.find('hostname')).text
            ritem['Last_Visit'] = ''
            if not (result.find('lastvisitdate')) is None:
                ritem['Last_Visit'] = (result.find('lastvisitdate')).text
            ritem['Last_Visit_Local'] = ''
            if not (result.find('lastvisitdatelocal')) is None:
                ritem['Last_Visit_Local'] = (result.find('lastvisitdatelocal')).text
            ritem['Profile'] = ''
            if not (result.find('profile')) is None:
                ritem['Profile'] = (result.find('profile')).text
            ritem['Typed'] = ''
            if not (result.find('typed')) is None:
                ritem['Typed'] = (result.find('typed')).text
            ritem['URL'] = ''
            if not (result.find('url')) is None:
                ritem['URL'] = (result.find('url')).text
            ritem['Username'] = ''
            if not (result.find('username')) is None:
                ritem['Username'] = (result.find('username')).text
            ritem['Visit_Count'] = ''
            if not (result.find('visitcount')) is None:
                ritem['Visit_Count'] = (result.find('visitcount')).text
            ritem['Visit_From'] = ''
            if not (result.find('visitfrom')) is None:
                ritem['Visit_From'] = (result.find('visitfrom')).text
            ritem['Visit_Type'] = ''
            if not (result.find('visittype')) is None:
                ritem['Visit_Type'] = (result.find('visittype')).text
            OutputData.out_url_hit(ritem, False)

    @staticmethod
    def hit_event():
        global start_dir
        global endpoint
        global xml_path
        global trt_root
        # EventHit
        for result in trt_root.iter('eventitem'):
            eitem = ModelData.EventItemHit
            eitem['XML'] = os.path.basename(xml_path)
            eitem['Endpoint'] = endpoint
            eitem['EventID'] = ''
            if not (result.find('eid')) is None:
                eitem['EventID'] = (result.find('eid')).text
            eitem['SourceLog'] = ''
            if not (result.find('channel')) is None:
                eitem['SourceLog'] = (result.find('channel')).text
            eitem['Computer'] = ''
            if not (result.find('computer')) is None:
                eitem['Computer'] = (result.find('computer')).text
            eitem['Source'] = ''
            if not (result.find('source')) is None:
                eitem['Source'] = (result.find('source')).text
            eitem['User'] = ''
            if not (result.find('user')) is None:
                eitem['User'] = (result.find('user')).text
            eitem['GenerationTime'] = ''
            if not (result.find('genTime')) is None:
                eitem['GenerationTime'] = (result.find('genTime')).text
            eitem['WriteTime'] = ''
            if not (result.find('writeTime')) is None:
                eitem['WriteTime'] = (result.find('writeTime')).text
            eitem['PID'] = ''
            if not (result.find('processID')) is None:
                eitem['PID'] = (result.find('processID')).text
            eitem['ThreadID'] = ''
            if not (result.find('threadID')) is None:
                eitem['ThreadID'] = (result.find('threadID')).text
            eitem['CategoryNumber'] = ''
            if not (result.find('categoryNum')) is None:
                eitem['CategoryNumber'] = (result.find('categoryNum')).text
            eitem['RecordID'] = ''
            if not (result.find('recordID')) is None:
                eitem['RecordID'] = (result.find('recordID')).text
            eitem['Message'] = ''
            if not (result.find('message')) is None:
                eitem['Message'] = (result.find('message')).text

            OutputData.out_event_hit(eitem, False)

    @staticmethod
    def hit_module_error():
        global start_dir
        global endpoint
        global xml_path
        global trt_root
        # Module Error
        for error in trt_root.iter('warningindicator'):
            eitem = ModelData.ModuleErrorItemHit
            eitem['XML'] = os.path.basename(xml_path)
            eitem['Endpoint'] = endpoint
            eitem['Error'] = ''
            if not (error.find('message')) is None:
                eitem['Error'] = (error.find('message')).text
            OutputData.out_err(eitem, False)

    @staticmethod
    def parse_threat():
        global start_dir
        global endpoint
        global xml_path
        global trt_root
        # Parse the XML from the threat.xml file
        try:
            tree = eT.parse(xml_path)
            trt_root = tree.getroot()
        except eT.ParseError as e:
            # Exception, print and log it
            print('Error reading XML for {0} at {1}: {2}\n'.format(endpoint, xml_path, e))
            with open(start_dir + FileNames['exception'], 'a') as outFile:
                outFile.write('Error reading XML for {0} at {1}: {2}\n'.format(endpoint, xml_path, e))

        # Reference global Hit Type Function Map
        global ThreatFunctions

        # Reference global HitCounts
        global HitCounts

        # Update stats in HitCounts
        for child in trt_root:
            if child.tag == 'FileItemList':
                if HitCounts['file'] == 0:
                    OutputData.out_file_hit(None, True)
                HitCounts['file'] += 1
            elif child.tag == 'warningindicatorlist':
                if HitCounts['warning'] == 0:
                    OutputData.out_err(None, True)
                HitCounts['warning'] += 1
            elif child.tag == 'EventLogtemList':
                if HitCounts['event'] == 0:
                    OutputData.out_event_hit(None, True)
                HitCounts['event'] += 1
            elif child.tag == 'RegistryItemList':
                if HitCounts['reg'] == 0:
                    OutputData.out_reg_hit(None, True)
                HitCounts['reg'] += 1
            elif child.tag == 'URLHistoryItemList':
                if HitCounts['url'] == 0:
                    OutputData.out_url_hit(None, True)
                HitCounts['url'] += 1
            elif child.tag == 'TruncatedItemList':
                if HitCounts['truncated'] == 0:
                    OutputData.out_truncated_hit(None, True)
                HitCounts['truncated'] += 1
            elif child.tag == 'ProcessItemList':
                if HitCounts['proc'] == 0:
                    OutputData.out_proc_hit(None, True)
                HitCounts['proc'] += 1

            try:
                # Execute function to parse hit
                ThreatFunctions[child.tag]()
            except BaseException as e:
                # Exception, print and log it
                print('!!!!! Unknown Key: {0} in {1}. Please report this!!!!\n'.format(e, xml_path))
                with open(start_dir + FileNames['exception'], 'a') as outFile:
                    outFile.write('!!!!! Unknown Key: {0} in {1}. Please report this!!!!\n'.format(e, xml_path))

# Define the function per hit type
ThreatFunctions = {
    'FileItemList': ParseThreats.hit_file,
    'warningindicatorlist': ParseThreats.hit_module_error,
    'EventLogtemList': ParseThreats.hit_event,
    'RegistryItemList': ParseThreats.hit_reg,
    'URLHistoryItemList': ParseThreats.hit_url,
    'TruncatedItemList': ParseThreats.hit_truncated,
    'ProcessItemList': ParseThreats.hit_proc,
}

if __name__ == "__main__":
    parseargs()


