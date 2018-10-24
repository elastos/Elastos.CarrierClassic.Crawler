import sys
import urllib
import json

__API_KEY = '4a841e9f830dd6e6fdd441b264614677'
__API_URL = 'http://api.ipstack.com/{0}?access_key={1}'

def ip2geoinfo(address):
    url = __API_URL.format(address, __API_KEY)
    response = urllib.urlopen(url)
    data = json.loads(response.read())
    return '{}, {}, {}'.format(data['continent_name'], data['country_name'], data['city'])

def process_crawler_log(path, output):
    output = open(output, 'w')

    with open(path) as log:
        line = log.readline().strip()
        while line:
            toks = line.split(' ')
            node = toks[0]
            address = toks[1]
            geo = ip2geoinfo(address)
            result = '{} {}\t\t{}\n'.format(node, address, geo)
            output.write(result)
            line = log.readline().strip()

    output.close()

if __name__== "__main__":
    if len(sys.argv) != 3:
        print 'ip2geo crawler-log-file output-file'
        exit(0)

    process_crawler_log(sys.argv[1], sys.argv[2])
