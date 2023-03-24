
import argparse
from collections import namedtuple
import configparser
import datetime
import json
import logging
import logging.config
#import os.path
from pathlib import Path
import sqlite3
import sys
import time
import unicodedata
import urllib.request
import yaml


#https://docs.python.org/3/howto/unicode.html#comparing-strings
def normalizeString(s1):
    def NFD(s):
        return unicodedata.normalize('NFD', s)
    return NFD(NFD(s1).casefold())


class MeshStats:
    def __init__(self, logger):
        self.logger = logger
        self.numBytesRead = 0
        self.numQueriedNodes = 0
        self.numUniqueNodes = 0
        self.numNodeReadFailed = 0
        self.numFakeNodes = 0
        self.numLinks = 0
        self.numMatchedLinks = 0
        self.numTunnels = 0
        self.numRF = 0
        self.numDTD = 0
           
    def accumulateNumBytesRead(self, n):
        self.numBytesRead += n
    
    def incNumQueriedNodes(self):
        self.numQueriedNodes += 1
        
    def incNumUniqueNodes(self):
        self.numUniqueNodes += 1
        
    def incNumNodeReadFailed(self):
        self.numNodeReadFailed += 1
        
    def incNumFakeNodes(self):
        self.numFakeNodes += 1
         
    def incNumLinks(self):
        self.numLinks += 1
        
    def incNumMatchedLinks(self):
        self.numMatchedLinks += 1
        
    def incNumTunnels(self):
        self.numTunnels += 1
       
    def incNumRF(self):
        self.numRF += 1

    def incNumDTD(self):
        self.numDTD += 1
        
    def logStats(self, msg = ''):
        self.logger.info('Read {} bytes; Queried {} nodes ({} unique), {} read fail, {} fake, {} links, {} matched links ({} RF, {} tunnels, {} DTD){}'.format(
            self.numBytesRead,
            self.numQueriedNodes,
            self.numUniqueNodes,
            self.numNodeReadFailed,
            self.numFakeNodes,
            self.numLinks,
            self.numMatchedLinks,
            self.numRF, 
            self.numTunnels, 
            self.numDTD,
            msg))

    def printStats(self, msg = '', dest = sys.stderr):
        print('Read {} bytes; Queried {} nodes ({} unique), {} read fail, {} fake, {} links, {} matched links ({} RF, {} tunnels, {} DTD){}'.format(
            self.numBytesRead,
            self.numQueriedNodes,
            self.numUniqueNodes,
            self.numNodeReadFailed,
            self.numFakeNodes,
            self.numLinks,
            self.numMatchedLinks,
            self.numRF, 
            self.numTunnels, 
            self.numDTD,
            msg), file = dest)


def getLinkIP(interfaces, interfaceName):
    for interface in interfaces:
        try:
            if interface['name'] == interfaceName:
                return interface['ip']
        except Exception as err:
            logging.debug('Failed to find interface name {}'.format(err))
            
    return None


def saveLinkInfo(sessionID, pendingNodes, nodeName, sysInfo, stats, con, logger):
    try:
        links = sysInfo['link_info']
        for key in links:
            nearName = nodeName
            nearIP = getLinkIP(sysInfo['interfaces'], links[key]['olsrInterface'])
            farName = links[key]['hostname']
            farIP = key
            linkType = links[key]['linkType']
            linkType = normalizeString(linkType)
            priorLinkID = None
            farAddress = farName
            farAddress = normalizeString(farAddress)
            if farAddress.endswith('local.mesh') is False:
                farAddress += '.local.mesh'
            pendingNodes.append((farAddress, linkType, farName))

            # Check if the corresponding link from the destination node is already present
            # TBD maybe it's not a good idea to store the rowid. If the table is later modified the rowid for this record could change.
            logger.debug('Checking link ({} {}) to ({} {}) type {}'.format(nearName, nearIP, farName, farIP, linkType))
            cur = con.cursor()
            cur.execute('SELECT rowid FROM link WHERE session_id = ? AND near_node_name = ? AND far_node_name = ? AND link_type = ?', (sessionID, farName, nearName, linkType))
            row = cur.fetchone()
            logger.debug('Check if the corresponding link is already present {} {} {} {}: {} {}'.format(sessionID, farName, nearName, linkType, row, type(row)))
            if row is not None:
                priorLinkID = row.rowid
                stats.incNumMatchedLinks()
                
            logger.debug('Adding link record: session {} {} ({} {}) to ({} {})'.format(sessionID, linkType, nearName, nearIP, farName, farIP))

            # some entries are only present for certain link types
            try:
                signal = links[key]['signal']
            except KeyError:
                signal = None            
            try:
                noise = links[key]['noise']
            except KeyError:
                noise = None
            try:
                linkQuality = links[key]['linkQuality']
            except:
                linkQuality = None
            try:
                neighborLinkQuality = links[key]['neighborLinkQuality']
            except KeyError:
                neighborLinkQuality = None
            try:                
                linkCost = links[key]['linkCost']
            except:
                linkCost = None
            try:
                rx_rate = links[key]['rx_rate']
            except KeyError:
                rx_rate = None            
            try:
                tx_rate = links[key]['tx_rate']
            except KeyError:
                tx_rate = None
            try:
                expected_throughput = links[key]['expected_throughput']
            except KeyError:
                expected_throughput = None
                
            cur.execute("""
                INSERT INTO link(session_id, reverse_link, near_node_ip, near_node_name, far_node_ip, far_node_name, 
                link_type, signal, noise, link_quality, neighbor_link_quality, link_cost, 
                rx_rate, tx_rate, expected_throughput) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, 
                (
                sessionID,
                priorLinkID,            
                nearIP, 
                nearName, 
                farIP, 
                farName, 
                linkType,
                signal,
                noise,
                linkQuality,
                neighborLinkQuality,
                linkCost,
                rx_rate,
                tx_rate,
                expected_throughput)
                )
                
            # If the corresponding link from the destination is present, associate it with the new record    
            if priorLinkID is  not None:
                newLinkID = cur.lastrowid
                cur.execute('UPDATE link SET reverse_link = ? WHERE rowid = ?', (newLinkID, priorLinkID))
                
            con.commit()

            stats.incNumLinks()      
            if linkType == 'rf':
                stats.incNumRF()
            elif linkType == 'tun':
                stats.incNumTunnels()
            elif linkType == 'dtd':
                stats.incNumDTD()
            elif linkType == '': # Several mesh nodes have blank link type fields on DTD links.
                stats.incNumDTD()
            else:
                logger.error('Unexpected link type {} on link {} to {}'.format(linkType, nearName, farName))
    except KeyError:
        logger.warning('No link field is present in sys info for node {}'.format(nodeName))
    return pendingNodes


def saveNodeHistory(sessionID, nodeName, con, logger):
    logger.debug('Saving node history: {} {}'.format(sessionID, nodeName))
    cur = con.cursor()
    cur.execute('SELECT session_count FROM node_history WHERE name = ?', (nodeName,))
    row = cur.fetchone()
    logger.debug('Check if  node name {} already present in node history table {}: {}'.format(nodeName, row, type(row)))
    if row is None:
        sessionCount = 1
        cur.execute("""
            INSERT INTO node_history(initial_session_id, latest_session_id, name, session_count) 
            VALUES (?, ?, ?, ?)
            """, 
            (
            sessionID,
            sessionID,
            nodeName,
            sessionCount
            ))
    else:
        logger.debug('Update session count from row value {}'.format(row))
        sessionCount = row.session_count
        sessionCount += 1
        cur.execute("""
            UPDATE node_history SET
            latest_session_id = ?,
            session_count = ?
            WHERE name = ?
            """, (
            sessionID,
            sessionCount,
            nodeName))
    con.commit()        
    

def saveNodeInfo(sessionID, nodeAddress, sysInfo, stats, con, logger):
    logger.debug('Saving node info: {} {}'.format(sessionID, nodeAddress))
    stats.incNumUniqueNodes()
    saveNodeHistory(sessionID, sysInfo['node'], con, logger)
    
    # Some items are not present for some link types
    try:
        linkCount = len(sysInfo['link_info'])
    except KeyError:
        linkCount = None;
        logger.debug('No link_info field in sysInfo: {}'.format(sysInfo))
    try:
        lat = sysInfo['lat']
    except KeyError:
        lat = None;
        logger.debug('No lat field in sysInfo: {}'.format(sysInfo))
    try:
        lon = sysInfo['lon']
    except KeyError:
        lon = None;
        logger.debug('No lon field in sysInfo: {}'.format(sysInfo))
    try:
        firmware_version = sysInfo['node_details']['firmware_version'],
    except KeyError:
        firmware_version = None;
        logger.debug('No firmware_version field in sysInfo: {}'.format(sysInfo))
    try:
        api_version = sysInfo['api_version']
    except KeyError:
        api_version = None;
        logger.debug('No api_version field in sysInfo: {}'.format(sysInfo))
    try:
        model = sysInfo['node_details']['model']
    except KeyError:
        model = None;
        logger.debug('No model field in sysInfo: {}'.format(sysInfo))        
    try:
        channel = sysInfo['meshrf']['channel']
    except KeyError:
        channel = None
    try:
        freq = sysInfo['meshrf']['freq']
    except KeyError:
        freq = None
    try:
        chanbw = sysInfo['meshrf']['chanbw']
    except KeyError:
        chanbw = None
    try:
        status = sysInfo['meshrf']['status']
    except KeyError:
        status = None

    try:
        if type(firmware_version) is tuple:
            firmware_version = firmware_version[0]
        else:
            logger.error('firmware_version type is inconsistent: {} {} on node {}'.format(type(firmware_version), firmware_version, nodeAddress))
    except:
        logger.error('Unexpected firmware_version value: {} {} on node {}'.format(type(firmware_version), firmware_version, nodeAddress))

    try:  
        cur = con.cursor()
        cur.execute("""
            INSERT INTO node(session_id, address, name, link_count, lat, lon, 
                firmware_ver, api_ver, model, channel, freq, bw, rf_on) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, 
            (
            sessionID,
            nodeAddress,
            sysInfo['node'],
            linkCount,
            lat,
            lon,
            firmware_version,
            api_version,
            model,
            channel,
            freq,
            chanbw,
            status
            ))
        con.commit()
    except Exception as err:
        logger.error('Unable to write database record: {})'.format(err))


def saveFakeNodeInfo(sessionID, nodeAddress, linkType, nodeName, fakeInfo, stats, con, logger):
    if nodeAddress in fakeInfo['nodes'] and linkType == fakeInfo['nodes'][nodeAddress]['link_type']:
        logger.info('Saving fake node info: {} {} {} {} {} {}'.format(sessionID, nodeAddress, linkType, nodeName, fakeInfo['nodes'][nodeAddress]['name'], fakeInfo['nodes'][nodeAddress]['message']))
        stats.incNumUniqueNodes()
        stats.incNumFakeNodes()
        saveNodeHistory(sessionID, fakeInfo['nodes'][nodeAddress]['name'], con, logger)
        
        try:
            cur = con.cursor()
            cur.execute("""
                INSERT INTO node(session_id, address, name, link_count, lat, lon, 
                    firmware_ver, model, fake_data_date) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, 
                (
                sessionID,
                nodeAddress,
                fakeInfo['nodes'][nodeAddress]['name'],
                fakeInfo['nodes'][nodeAddress]['link_count'],
                fakeInfo['nodes'][nodeAddress]['lat'],
                fakeInfo['nodes'][nodeAddress]['lon'],
                fakeInfo['nodes'][nodeAddress]['firmware_ver'],
                fakeInfo['nodes'][nodeAddress]['model'],
                fakeInfo['nodes'][nodeAddress]['date_verified']
                ))
            con.commit()
        except Exception as err:
            logger.error('Unable to write database record: {})'.format(err))
    else:
        logger.warning('Did not find address {}, link type {} in fake node info'.format(nodeAddress, linkType))    

# https://arednmesh.readthedocs.io/en/latest/arednHow-toGuides/devtools.html
# http://<nodename>.local.mesh/cgi-bin/sysinfo.json
# http://<nodename>.local.mesh/cgi-bin/sysinfo.json?hosts=1
# http://<nodename>.local.mesh/cgi-bin/sysinfo.json?services=1
# http://<nodename>.local.mesh/cgi-bin/sysinfo.json?services_local=1
# http://<nodename>.local.mesh/cgi-bin/sysinfo.json?link_info=1
# http://<nodename>.local.mesh/cgi-bin/sysinfo.json?lqm=1
def traverseNode(sessionID, pendingNodes, timeoutSec, fakeInfo, stats, con, logger):    
    (nodeAddress, linkType, nodeName) = pendingNodes.pop()
    nodeAddress = normalizeString(nodeAddress)
    logger.debug('Processing node {} {}'.format(nodeAddress, nodeName))
        
    # Check if the target  node has already been processed in this session
    cur = con.cursor()
    cur.execute('SELECT session_id FROM node WHERE session_id = ? AND address = ?', (sessionID, nodeAddress))
    row = cur.fetchone()
    linkInfo = None
    logger.debug('Check if  node address {} already processed for sessionID {}: {} {}'.format(nodeAddress, sessionID, row, type(row)))
    if row is None:
        url_basic = 'http://' + nodeAddress
        url_links = url_basic + ':8080/cgi-bin/sysinfo.json?link_info=1'
        logger.debug('Collecting data from {}'.format(url_links))
                
        stats.incNumQueriedNodes()
        try:
            try:
                response = urllib.request.urlopen(url_links, timeout = timeoutSec)
                node_text = response.read().decode('ISO8859') # This encoding handles the degree symbol present in some mesh node descriptions for antenna azimuth, etc.
                try:    
                    stats.accumulateNumBytesRead(len(node_text))
                    linkInfo = json.loads(node_text)
                    if 'link_info' not in linkInfo:
                        raise(RuntimeError('Node has no link information: {}'.format(nodeName)))
                except (json.JSONDecodeError, UnicodeDecodeError, RuntimeError) as err:
                    logger.warning('Unable to parse info from node at {} {}, linkType {}: {}'.format(url_links, nodeName, linkType, err))
                    if node_text:
                        logger.debug(node_text)
                    saveFakeNodeInfo(sessionID, nodeAddress, linkType, nodeName, fakeInfo, stats, con, logger)
                    stats.incNumNodeReadFailed()
                    return pendingNodes
            except urllib.error.URLError as err:
                logger.warning('Unable to get info from node at {} {}, linkType {}: {}'.format(url_links, nodeName, linkType, err))
                stats.incNumNodeReadFailed()
                try:
                    # Check if the node will reply to a request for the usual status page.
                    # If so it may be running old software that doesn't support the current API.
                    # Use data which has been manually read from the status page and entered in exceptions file.
                    response = urllib.request.urlopen(url_basic, timeout = timeoutSec)
                    saveFakeNodeInfo(sessionID, nodeAddress, linkType, nodeName, fakeInfo, stats, con, logger)
                except urllib.error.URLError as err:
                    # Don't save a node record for this session if the node is unreachable
                    # TBD instead of trying to read the status page to discover if the node is active, check details of the initial failure to determine if the node responded at all
                    logger.warning('Unable to read HTML status page from node at {} {} {}: {}'.format(url_basic, nodeName, linkType, err))
                    return pendingNodes
        except Exception as err:
            logger.error('Unexpected error while processing node at {} {}, linkType {}: {}'.format(url_links, nodeName, linkType, err))
            saveFakeNodeInfo(sessionID, nodeAddress, linkType, nodeName, fakeInfo, stats, con, logger)
            stats.incNumNodeReadFailed()
            return pendingNodes

        if linkInfo:
            nodeName = linkInfo['node'] 
            saveNodeInfo(sessionID, nodeAddress, linkInfo, stats, con, logger)
            pendingNodes = saveLinkInfo(sessionID, pendingNodes, nodeName, linkInfo, stats, con, logger)
            if nodeAddress in fakeInfo['nodes']:
                logger.warning('Node read successful, but node is in exception file: {}'.format(nodeAddress))
            else:
                pass
    else:
        logger.debug('Found node {} again on mesh links'.format(nodeAddress))
    return pendingNodes


def beginSession(swVersion, originNodeName, con, logger):
    timestamp = datetime.datetime.now(datetime.timezone.utc)
    timestampString = str(timestamp)
    logger.info('Beginning session at node {} at {} UTC'.format(originNodeName, timestampString))
    status = 'Pending'
    try:
        cur = con.cursor()
        cur.execute("""
            INSERT INTO session(sw_ver, status, origin_node, start_time, tz_name) 
            VALUES (?, ?, ?, ?, ?)
            """, (swVersion, status, originNodeName, timestampString, timestamp.tzname()))
        con.commit()
    except Exception as err:
        logger.error("Unable to create session record: {}".format(err))
        raise
            
    return (timestampString, timestamp)


def endSession(sessionID, startTime, stats, con, logger):
    endTime = datetime.datetime.now(datetime.timezone.utc)
    timeDelta = endTime - startTime
    durationSec = int(round(timeDelta.total_seconds()))
    logger.debug('durationSec {} {}'.format(durationSec, type(durationSec)))
    status = 'Done'
    
    # TBD check if node and link counts match the database contents for this session
    cur = con.cursor()
    #nodes = cur.execute('SELECT session_id FROM node WHERE session_id = ?', (sessionID))
    #links = cur.execute('SELECT session_id FROM link WHERE session_id = ?', (sessionID))
    #logger.debug('Nodes: {}, Links {}'.format(len(nodes), len(links)))
    
    try:
        cur.execute("""
            UPDATE session SET
            status = ?, 
            duration_sec = ?, 
            num_queried_nodes = ?, 
            num_unique_nodes = ?,
            num_links = ?,
            num_matched_links = ?,            
            num_rf = ?, 
            num_dtd = ?, 
            num_tunnels = ? 
            WHERE start_time = ?
            """, (
            status, 
            durationSec, 
            stats.numQueriedNodes,
            stats.numUniqueNodes,
            stats.numLinks,
            stats.numMatchedLinks,
            stats.numRF, 
            stats.numDTD, 
            stats.numTunnels, 
            sessionID))
        con.commit()
    except Exception as err:
        logger.error("Unable to create session record: {}".format(err))
        raise
    
    logger.info('Ending session at {} UTC; run time {} seconds'.format(endTime, durationSec))


# https://docs.python.org/3/library/sqlite3.html?highlight=sqlite3#how-to-create-and-use-row-factories
def namedtuple_factory(cursor, row):
    fields = [column[0] for column in cursor.description]
    cls = namedtuple("Row", fields)
    return cls._make(row)


def openDB(databaseFileName, logger):
    logger.info('Opening database file {}'.format(databaseFileName))
    con = sqlite3.connect(databaseFileName)
    con.row_factory = namedtuple_factory
    
    cur = con.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS session(
            sw_ver string,
            status string,
            origin_node string,
            start_time string,
            tz_name string, 
            duration_sec integer DEFAULT NULL, 
            num_queried_nodes integer DEFAULT 0, 
            num_unique_nodes integer DEFAULT 0,
            num_links integer DEFAULT 0,
            num_matched_links integer DEFAULT 0,
            num_rf integer DEFAULT 0,
            num_dtd integer DEFAULT 0,
            num_tunnels integer DEFAULT 0,
            UNIQUE(start_time, tz_name))
            """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS node_history(
            initial_session_id string REQUIRED,
            latest_session_id string REQUIRED,
            name string REQUIRED,
            session_count integer REQUIRED,
            UNIQUE(name))
            """)
            
        cur.execute("""
            CREATE TABLE IF NOT EXISTS node(
            session_id string REQUIRED, 
            address string,
            name string DEFAULT NULL,
            link_count integer,
            lat real DEFAULT NULL,
            lon real DEFAULT NULL,
            firmware_ver string DEFAULT NULL,
            api_ver string DEFAULT NULL,
            model string DEFAULT NULL,
            channel string DEFAULT NULL,
            freq string DEFAULT NULL,
            bw string DEFAULT NULL,
            rf_on string DEFAULT NULL,
            fake_data_date string DEFAULT NULL,
            UNIQUE(session_id, name))
            """)
            
        cur.execute("""
            CREATE TABLE IF NOT EXISTS link(
            session_id string REQUIRED,
            reverse_link integer DEFAULT NULL,
            near_node_ip string,
            near_node_name string,
            far_node_ip string,
            far_node_name string,
            link_type string,
            signal integer,
            noise integer,
            link_quality integer,
            neighbor_link_quality integer,
            link_cost integer,
            rx_rate integer,
            tx_rate integer, 
            expected_throughput real,
            UNIQUE(session_id, near_node_name, far_node_name))
            """)
    except sqlite3.OperationalError as err:
        logger.error("Unable to create table: {}".format(err))
        raise
    con.commit()
    logger.debug('Opened database file')
    return con
        
 
def open_logger(fname, loggerName):
    try:
        with open(fname, 'r') as stream:
            try:
                d = yaml.safe_load(stream)
                logging.config.dictConfig(d)
                logger = logging.getLogger(loggerName)
                logger.info('Using logger configuration file {}'.format(fname))                
            except Exception as err:
                logger = logging.getLogger(loggerName)     
                logger.warning('Unable to configure logger using file {}: {}'.format(fname, err))
                raise
    except FileNotFoundError as err:
        logger = logging.getLogger(loggerName)            
        logger.warning('Unable to read logger configuration file {}: {}'.format(fname, err))
        raise
    return logger    


def showSettings(settings, logger):
        logger.info('Command line parameter values:' )
        logger.info('  originNodeName:         {}'.format(settings['originNodeName']))
        logger.info('  databaseFileName:       {}'.format(settings['databaseFileName']))
        logger.info('  reportPath:             {}'.format(settings['reportPath']))
        logger.info('  loggerConfigFileName:   {}'.format(settings['loggerConfigFileName']))
        logger.info('  nodeExceptionsFileName: {}'.format(settings['nodeExceptionsFileName']))
        logger.info('  maxNodes:               {}'.format(settings['maxNodes']))
        logger.info('  timeoutSeconds:         {}'.format(settings['timeoutSeconds']))
        logger.info('  scanInterval:           {}'.format(settings['scanInterval']))
        logger.info('  nodeDelay:              {}'.format(settings['nodeDelay']))
        logger.info('  verbosity:              {}'.format(settings['verbosity']))


def getSettings(appName, appVersion, appDescription, appEpilog, configPath):
    # Read the config file
    config_fname = '{}{}.cfg'.format(configPath, appName)
    config = configparser.ConfigParser()
    
    status = Path(config_fname)
    if not status.is_file():
        raise RuntimeError('Config file not found: {}'.format(config_fname))
    config.read(config_fname)
    
    # Allow the user to easily override settings from the command line
    parser = argparse.ArgumentParser(prog = appName, description = appDescription, epilog = appEpilog, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-o', '--origin_node', default=config['scan']['origin_node'], help='Name or address of the initial mesh node for the mesh crawl. Examples: N0CALL.local.mesh or 10.1.2.3')
    parser.add_argument('-d', '--db_fname', default=config['files']['db_fname'], help='Name of the sqlite database file to use (or create if not present)')
    parser.add_argument('-r', '--report_path', default= config['files']['report_path'], help='Path for report file output')
    parser.add_argument('-l', '--logger_config_fname', default=config['files']['logger_config_fname'], help='Logger configuration file (see https://docs.python.org/3/library/logging.html')
    parser.add_argument('-e', '--exceptions_fname', default=config['files']['exceptions_fname'], help='JSON file containing node information to represent known unreadable nodes')
    parser.add_argument('-m', '--max_nodes', type=int, default=config['scan']['max_nodes'], help='Maximum number of mesh nodes to query. Set it to around 50%% more than the expected number of nodes on the mesh.')
    parser.add_argument('-t', '--timeout', type=int, default=config['scan']['timeout_sec'], help='Maximum waiting time (in seconds) for a response to a node query')
    parser.add_argument('-i', '--scan_interval', type=int, default=config['scan']['mesh_scan_interval_sec'], help='Time between mesh scan sessions (in seconds)')
    parser.add_argument('-n', '--node_delay', type=int, default=config['scan']['poll_delay_ms'], help='Time delay between accessing subsequent nodes (in milliseconds)')
    parser.add_argument('-v', '--verbosity', type=int, default=0, choices=[0, 1, 2], help='0 for minimal progress messages, larger values for more information')
    parser.add_argument('--version', action='version', version='{} {}'.format(appName, appVersion))

    args = parser.parse_args()
    settings = {
        'originNodeName': args.origin_node,
        'databaseFileName': args.db_fname,
        'reportPath': args.report_path,
        'loggerConfigFileName': args.logger_config_fname,
        'nodeExceptionsFileName': args.exceptions_fname,
        'maxNodes': args.max_nodes,
        'timeoutSeconds': args.timeout,
        'scanInterval': args.scan_interval,
        'nodeDelay': args.node_delay, 
        'verbosity': args.verbosity
        }
    return settings


if __name__ == "__main__":
    appVersion = '0.2.0'
    appName = (sys.argv[0])
    index = appName.rfind('.py')
    appName = appName[0:index]
    appDescription = 'Tool to store information about nodes and links in an AREDN ham radio mesh system.'.format(appVersion)
    appDescriptionEpilog = """Results are accumulated in an sqlite database, for display by other tools.
        See https://www.arednmesh.org/ for general information about the mesh network. """
    configPath = "..//config//"
    
    settings = getSettings(appName, appVersion, appDescription, appDescriptionEpilog, configPath)
    logger = open_logger(settings['loggerConfigFileName'], appName)
    logger.info('Starting {} version {}'.format(appName, appVersion))
    showSettings(settings, logger)
    stats = MeshStats(logger)
    con = openDB(settings['databaseFileName'], logger)
    
    # Read the  node exceptions file, which has information added to the results for nodes which are unreadable via the standard API due to old software and the like
    try:
        logger.info('Reading mesh node exception file {}'.format(settings['nodeExceptionsFileName']))
        with open(settings['nodeExceptionsFileName']) as file:
            meshExceptions = json.load(file)
    except Exception as err:
        print('Unable to read mesh exception file: {}'.format(err))
        raise

    try:
        # Mesh node addresses are added to the pendingNodes list as links are examined.
        # Keep crawing the mesh until all discovered nodes have been examined or the maxNodes limit is reached.
        pendingNodes = []
        (sessionID, startTime) = beginSession(appVersion, settings['originNodeName'], con, logger)
        pendingNodes.append((settings['originNodeName'], 'DTD', settings['originNodeName']))
        try:
            while pendingNodes:
                if stats.numQueriedNodes > settings['maxNodes']:
                    raise RuntimeError('Exceeded the max number of node queries: {} {}'.format(stats.numQueriedNodes, settings['maxNodes']))
                time.sleep(settings['nodeDelay']/1000)
                print(pendingNodes)
                pendingNodes = traverseNode(sessionID, pendingNodes, settings['timeoutSeconds'], meshExceptions, stats, con, logger)
                stats.printStats(', {} pending Nodes)'.format(len(pendingNodes)), sys.stderr)
            stats.logStats(', Successful completion)')    
        except RuntimeError as err:
            logger.error(err)
        finally:
            endSession(sessionID, startTime, stats, con, logger)            
    except RuntimeError as err:
        logger.error(err)
    finally:
        logger.info('Closing database')
        con.close()

