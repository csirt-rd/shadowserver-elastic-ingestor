#!/usr/bin/env python3
#
# Copyright 2023 The Shadowserver Foundation, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

import sys
import os
import json
import hashlib
import hmac
import re
import csv
import time
import configparser
import logging
import ecs_logging
from urllib.request import urlopen, urlretrieve, Request
from datetime import datetime, timedelta, timezone


MAPURL = 'https://interchange.shadowserver.org/elasticsearch/v1/map'
APIROOT = 'https://transform.shadowserver.org/api2/'
DLROOT = 'https://dl.shadowserver.org/'
TIMEOUT = 45
MAX_AGE = 86400 * 7 # 7 days
MAX_AGE_FILEBEAT_LOGS = 86400 / 2 # 12 hours

datetime_patterns = [
    r".*\.timestamp",
    r".*_timestamp",
    r".*\.not_after",
    r".*\.not_before",
    r".*\.accessed",
    r"^created$",
    r".*\.created",
    r".*\.installed",
    r".*\.creation_date",
    r".*\.ctime",
    r".*\.mtime",
    r"^ingested$",
    r".*\.ingested",
    r".*\.start",
    r".*\.end",
    r".*\.indicator\.first_seen",
    r".*\.indicator\.last_seen",
    r".*\.indicator\.modified_at",
    r".*threat\.enrichments\.matched\.occurred"
]


def set_timestamp(event, field, value):
    """
    Convert timestamp to isoformat.

    param event: An event dictionary
    param field: The source field name
    param value: The source field value
    """
    event['timestamp'] = value.replace(' ', 'T')+'Z'


def set_tags(event, field, value):
    """
    Split tag values into a list.

    param event: An event dictionary
    param field: The source field name
    param value: The source field value
    """
    event['tags'] = re.split('[,;]', value)


def set_labels(event, field, value, args):
    """
    Add a named label from a field value.

    param event: An event dictionary
    param field: The source field name
    param value: The source field value
    param args:  A list of arguments
    """
    if 'labels' not in event:
        event['labels'] = {}
    try:
        event['labels'][args[0]] = value
    except Exception:
        pass


class ECSFormatter(ecs_logging.StdlibFormatter):
    """
    Work-around for "Type mismatch at key `@timestamp`: merging dicts".
    """

    def format_to_ecs(self, record):
        result = super().format_to_ecs(record)
        del result['message']  # remove empty element
        result['@timestamp'] = result.pop('timestamp')
        return result


class ShadowserverECSLogger:
    """
    Connects to the Shadowserver API to obtain and stream reported events.
    """
    datetime_field_pattern = re.compile("|".join(datetime_patterns))
    functions = {
        'timestamp': set_timestamp,
        'labels': set_labels,
        'tags': set_tags,
    }
    map_filename = 'map.json'
    ignored_reports: set[str] = set()

    _func_pattern = re.compile("^&([^(]+)")
    _func_args_pattern = re.compile("^&([^(]+)\(([^)]+)\)")

    def __init__(self, args):
        """
        Initialize the logger.

        :param config_file: path to a configuration file
        """
        if len(args) < 2:
            raise ValueError("Usage: %s /path/to/config.ini [ update ]" % (args[0]))
        if len(args) > 2:
            self.mode = args[2]
        else:
            self.mode = 'run'

        self.config = configparser.ConfigParser()
        self.config.read(args[1])

        self.state_directory = self.config.get('general', 'state_directory')
        self.apikey = self.config.get('general', 'apikey')
        self.secret = self.config.get('general', 'secret')

        if "exclude_reports" in self.config['general']:
            self.ignored_reports = set(self.config.get('general', 'exclude_reports').split(','))

        self.logger = logging.getLogger('app')
        self.logger.setLevel(logging.DEBUG)

        if not os.path.isdir(self.state_directory):
            raise ValueError('general.state_directory %r does not exist'
                             % (self.state_directory))

        if self.config.getboolean('general', 'auto_update'):
            self.update()

        map_path = os.path.join(self.state_directory, self.map_filename)
        with open(map_path) as fh:
            self.mapping = json.load(fh)


    def execute(self):
        if self.mode == "update":
            return

        if self.mode == "run":
            self.run()
            return


    def get_all_except(self, date_str: str, ignored_types: set[str]) -> list[dict[str, str]]:
        reports: list[dict[str, str]] | None = self._api_call('reports/list', {"date": date_str})

        if not reports:
            return []

        return [report for report in reports if report["type"] not in ignored_types and report["type"] not in self.config]
    

    def expire_old_files(self, directory: str, max_age: int = MAX_AGE):
        """
        Remove old files from target directory.

        :param directory: the directory
        :param max_age: max age of file in the directory
        """
        for file in os.listdir(directory):
            path = os.path.join(directory, file)
            if os.path.isfile(path):
                fstat = os.stat(path)
                if time.time() - fstat.st_mtime > max_age:
                    os.unlink(path)

    
    def prepare_directory(self, parent_directory: str, directory_name: str) -> str:
        """
        Use target directory to download the reports. If directory does not exist, it will create it.

        :param parent_directory: directory that contains the specified directory name
        :param directory_name: directory name that will be used and/or created
        """
        name = os.path.basename(directory_name)
        dst = os.path.join(parent_directory, name)
        
        if not os.path.isdir(dst):
            os.mkdir(dst)

        return dst


    def download_specifics(self, date_str: str):
        for input_name in self.config:
            input_item = self.config[input_name]
            if 'log' not in input_item:
                continue
            if not os.path.isdir(input_item['log']):
                print("ERROR: log must be a directory for %r" % (input_name))
                exit(1)

            types = None
            request = {'date': date_str}
            if 'reports' in input_item:
                request['reports'] = input_item['reports'].split(',')
            if 'types' in input_item:
                types = input_item['types'].split(',')

            # prepare input specific checkpoint directory
            dst = self.prepare_directory(self.state_directory, input_name)

            # locate new reports
            reports = self._api_call('reports/list', request)
            if reports is not None:
                for report in reports:
                    if types is not None:
                        if report['type'] not in types:
                            continue
                    path = os.path.join(dst, report['file'])
                    if not os.path.exists(path):
                        if self._download(report, path):
                            self._stream_events(input_item['log'], report, path)
                            # truncate the file to conserve space
                            fh = open(path, 'a')
                            fh.truncate(0)
                            fh.close()

            # expire old files
            self.expire_old_files(dst)


    def download_all_except(self, date_str: str, exclude_reports: set[str]):
        reports = self.get_all_except(date_str, exclude_reports)

        if not reports or len(reports) <= 0:
            return

        dst = self.prepare_directory(self.state_directory, 'general')
        log_dst = self.prepare_directory('/var/lib/ecs', 'filebeat')

        for report in reports:
            path = os.path.join(dst, report['file'])
            if not os.path.exists(path):
                if self._download(report, path):
                    self._stream_events(log_dst, report, path)
                    
                    # truncate the file to conserve space
                    with open(path, 'a') as fh:
                        fh.truncate(0)
        
        self.expire_old_files(dst)
        self.expire_old_files(log_dst, MAX_AGE_FILEBEAT_LOGS)


    def run(self):
        date = datetime.now(timezone.utc).date()
        begin = date - timedelta(2)
        date_str = f'{begin.isoformat()}:{date.isoformat()}'

        if len(self.config) > 2:
            self.download_specifics(date_str)

        if len(self.ignored_reports) > 0:
            self.download_all_except(date_str, self.ignored_reports)


    def update(self):
        """
        Update the field mapping.
        """
        map_tmp = os.path.join(self.state_directory, '.' + self.map_filename)
        map_path = os.path.join(self.state_directory, self.map_filename)

        status = False
        try:
            urlretrieve(MAPURL, map_tmp)
            if os.path.getsize(map_tmp) > 0:
                with open(map_tmp) as fh:
                    mapping = json.load(fh)
                status = True
        except Exception as e:
            print("ERROR: Download failed: %s" % (str(e)))

        if status:
            print("INFO: Mapping downloaded successfully")
            os.rename(map_tmp, map_path)
        else:
            if os.path.isfile(map_tmp):
                os.unlink(map_tmp)

        return status

    def _stream_events(self, log, report, path):
        """
        Import events from the specified report.

        :param logger: a Logger object
        :param report: a dictonary
        :param path: string
        """
    
        logfile = os.path.join(log, re.sub('.csv$', '.json', os.path.basename(path)))
        handler = logging.FileHandler(logfile)
        handler.setFormatter(ECSFormatter())
        self.logger.addHandler(handler)

        count = 0
        with open(path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                event = {}
                count += 1
                for field in row:
                    value = row[field]

                    if value == "":
                        continue

                    mapped = self._map_field(field, report['type'])

                    if mapped.startswith("&"):
                        self._execute_function(event, mapped, field, value)
                        continue

                    event[mapped] = self._transform_field(mapped, value)
                event['event.dataset'] = report['type']
                self.logger.info('', extra=event)

        self.logger.removeHandler(handler)
        print("INFO: Processed %d events for %r" % (count, report['file']))

    
    def _transform_field(self, mapped_field: str, value: str):
        if self.datetime_field_pattern.match(mapped_field):
            parsed_date = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            return parsed_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        return value


    def _execute_function(self, event, mapped_fieldname, fieldname, value):
        m = self._func_args_pattern.match(mapped_fieldname)
        if m:
            groups = m.groups()
            func = groups[0]
            args = groups[1].split(',')
            if func in self.functions:
                self.functions[func](event, fieldname, value, args)
                return

        m = self._func_pattern.match(mapped_fieldname)
        if m:
            func = m.groups()[0]
            if func in self.functions:
                self.functions[func](event, fieldname, value)
                return

    def _map_field(self, field: str, report_type: str) -> str:
        if field in self.mapping['map']:
            return self.mapping['map'][field]
        
        name = f"{report_type}.{field}"

        if name in self.mapping['map']:
            return self.mapping['map'][name]
        
        return f"extra.{field}"

    def _api_call(self, method, request):
        """
        Call the specified api method with a request dictionary.

        :param method: string
        :param request: dictionary
        """
        url = APIROOT + method

        request['apikey'] = self.apikey
        request_string = json.dumps(request)

        secret_bytes = bytes(str(self.secret), 'utf-8')
        request_bytes = bytes(request_string, 'utf-8')

        hmac_generator = hmac.new(secret_bytes, request_bytes, hashlib.sha256)
        hmac2 = hmac_generator.hexdigest()

        result = None
        response = None
        try:
            ua_request = Request(url, data=request_bytes, headers={'HMAC2': hmac2})
            response = urlopen(ua_request, timeout=TIMEOUT)
        except Exception as e:
            raise ValueError("API Exception %s" % format(e))
        try:
            result = json.loads(response.read())
        except Exception as e:
            raise ValueError("Exception: unable to parse output for {}: {}".format(request, format(e)))
        return result

    def _download(self, report, path):
        """
        Download a report.  Returns True on success.

        :param report: dictionary
        :param path: string
        """
        status = False
        try:
            urlretrieve(DLROOT + report['id'], path)
            if os.path.getsize(path) > 0:
                status = True
        except Exception as e:
            print("ERROR: Download failed: %s" % (str(e)))
            os.unlink(path)
        return status


if __name__ == "__main__":
    sys.exit(ShadowserverECSLogger(sys.argv).execute())