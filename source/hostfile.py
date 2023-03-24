import json
from operator import itemgetter
import sys
from urllib.request import urlopen

# Make a numeric sort key from the dotted IP address string for convenience
def ipToSortKey(ip):
    # for basic testing of this function
    #ip = '10.110.12'
    #ip = '10.110.12.99.3'
    #ip = '10.110.12.abc'

    key = 0;
    parts = ip.split('.')
    if len(parts) != 4:
        raise RuntimeError('IP address {} not in expected dotted format'.format(ip))
    try:
        for part in parts:
            key = 1000*key + int(part)
    except Exception as err:
        raise RuntimeError('Error while converting IP address {} to key: {}'.format(ip, err))
    return key


# https://arednmesh.readthedocs.io/en/latest/arednHow-toGuides/devtools.html
# http://<nodename>.local.mesh/cgi-bin/sysinfo.json?hosts=1
def getHostsTable(node):
    print('Showing host table from {}'.format(nodeName), file = sys.stderr)
    url = 'http://' + node + '/cgi-bin/sysinfo.json?hosts=1'
    #url = 'http://' + node + '.local.mesh/cgi-bin/sysinfo.json?hosts=1'
    try:
        rawResponse = urlopen(url)
    except:
        raise RuntimeError('Error getting host table from {}'.format(url))
    response = json.loads(rawResponse.read())
    hosts = response['hosts']
    for item in hosts:
        item['key'] = ipToSortKey(item['ip'])
    byName = sorted(hosts, key = itemgetter('name'))
    byIP = sorted(hosts, key = itemgetter('key'))
    print('Name Sort,IP,Name,IP Sort')
    print('Host table has {} entries.'.format(len(hosts)), file=sys.stderr)
    for index in range(1,len(hosts)):
        print('{},{},{},{}'.format(
        byName[index]['name'], byName[index]['ip'],
        byIP[index]['name'], byIP[index]['ip']))


if __name__ == "__main__":
    appVersion = '1.0.0'
    appName = sys.argv[0]
    if len(sys.argv) >= 2:
        nodeName = sys.argv[1]
    else:
        raise RuntimeError('{} {} You must specify an AREDN node name or IP address on the command line.\nExample: {} N0CALL.local.mesh\nExample: {} 10.1.1.10'.format(appName, appVersion, appName, appName))

    print('{} version {}'.format(appName, appVersion), file = sys.stderr)
    try:
        getHostsTable(nodeName)
        print('Completed', file = sys.stderr)
    except RuntimeError as err:
        print('{}'.format(err), file = sys.stderr)
        