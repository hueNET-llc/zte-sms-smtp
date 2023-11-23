import colorlog
import logging
import json
import os
import re
import requests
import sys

from base64 import b64encode
from datetime import datetime
from hashlib import md5
from smtplib import SMTP
from time import sleep


log = logging.getLogger('SMS')


class SMS:
    def __init__(self):
        # Setup logging
        self._setup_logging()

        # Modem firmware version, fetched after login
        self.wa_inner_version = ''

        self.blacklist = {
            'numbers': [],
            'words': []
        }

        # Load environment variables
        self._load_env_vars()
        # Load the SMS blacklist
        self._load_blacklist()
        # Create a new HTTP client
        self.http = requests.Session()

    def _setup_logging(self):
        """
            Sets up logging colors and formatting
        """
        # Create a new handler with colors and formatting
        shandler = logging.StreamHandler(stream=sys.stdout)
        shandler.setFormatter(colorlog.LevelFormatter(
            fmt={
                'DEBUG': '{log_color}{asctime} [{levelname}] {message}',
                'INFO': '{log_color}{asctime} [{levelname}] {message}',
                'WARNING': '{log_color}{asctime} [{levelname}] {message}',
                'ERROR': '{log_color}{asctime} [{levelname}] {message}',
                'CRITICAL': '{log_color}{asctime} [{levelname}] {message}',
            },
            log_colors={
                'DEBUG': 'blue',
                'INFO': 'white',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'bg_red',
            },
            style='{',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        # Add the new handler
        logging.getLogger('SMS').addHandler(shandler)
        log.debug('Finished setting up logging')

    def _load_env_vars(self):
        """
        Load and process environment variables
        """
        # Log level to use
        # 10/debug  20/info  30/warning  40/error
        try:
            self.log_level = int(os.environ.get('LOG_LEVEL', 20))
        except ValueError:
            log.exception('Invalid LOG_LEVEL environment variable, must be a number')
            exit(1)

        # Set the logging level
        logging.root.setLevel(self.log_level)

        try:
            self.modem_ip = os.environ['MODEM_IP']
        except ValueError:
            log.error('Missing MODEM_IP environment variable')
            exit(1)

        try:
            self.modem_password = os.environ['MODEM_PASSWORD']
        except ValueError:
            log.error('Missing MODEM_PASSWORD environment variable')
            exit(1)

        try:
            self.smtp_sender = os.environ['SMTP_SENDER']
        except ValueError:
            log.error('Missing SMTP_SENDER environment variable')
            exit(1)

        try:
            self.smtp_recipients = os.environ['SMTP_RECIPIENTS'].split(',')
        except ValueError:
            log.error('Missing SMTP_RECIPIENTS environment variable')
            exit(1)
        if len(self.smtp_recipients) == 0:
            log.error('SMTP_RECIPIENTS environment variable must contain at least one recipient')
            exit(1)

        log.info(f'Loaded {len(self.smtp_recipients)} SMTP recipients: {self.smtp_recipients}')

        # Optional SMTP settings
        # Login is not required
        self.smtp_username = os.environ.get('SMTP_USERNAME')
        self.smtp_password = os.environ.get('SMTP_PASSWORD')
        self.smtp_subject_prefix = os.environ.get('SMTP_SUBJECT_PREFIX', '')

        try:
            self.smtp_host = os.environ['SMTP_HOST']
        except ValueError:
            log.error('Missing SMTP_HOST environment variable')
            exit(1)

        # Get the SMTP port and ensure it's a valid port number
        try:
            self.smtp_port = int(os.environ.get('SMTP_PORT', 25))
        except ValueError:
            log.exception('Invalid SMTP_PORT environment variable, must be a number')
            exit(1)

        # Get the SMTP TLS setting and ensure it's a valid boolean
        try:
            self.smtp_tls = bool(os.environ.get('SMTP_TLS', False))
        except ValueError:
            log.exception('Invalid SMTP_TLS environment variable, must be a boolean')
            exit(1)

        # Get the Delete SMS setting
        try:
            self.inbox_delete_sms = bool(os.environ.get('MODEM_DELETE_SMS', True))
        except ValueError:
            log.exception('Invalid DELETE_SMS environment variable, must be a boolean')
            exit(1)

        try:
            self.inbox_fetch_interval = int(os.environ.get('MODEM_SMS_INBOX_FETCH_INTERVAL', 30))
        except ValueError:
            log.exception('Invalid MODEM_SMS_INBOX_FETCH_INTERVAL environment variable, must be a number')
            exit(1)

    def _load_blacklist(self):
        """
        Load the SMS word and number blacklist from a JSON file blacklist.json
        """
        try:
            with open('blacklist.json', 'r') as f:
                blacklist = json.load(f)
                for word in blacklist.get('words', []):
                    self.blacklist['words'].append(re.compile(word))
                for number in blacklist.get('numbers', []):
                    self.blacklist['numbers'].append(re.compile(number))
            log.info(f'Loaded blacklist with {len(self.blacklist["words"])} words and {len(self.blacklist["numbers"])} numbers')
        except FileNotFoundError:
            log.info('blacklist.json not found, not using a blacklist')
            self.blacklist = []
        except json.decoder.JSONDecodeError:
            log.warning('blacklist.json does not contain valid JSON')

    def decode_sms_content(self, content: str) -> str:
        """
        Decode the SMS content from hexadecimals to ASCII

        Args:
            content (str): Hexadecimal encoded SMS content

        Returns:
            str: ASCII decoded SMS content
        """
        # Convert the content from hexadecimals to ASCII
        try:
            # Try to decode to UTF-8 first
            decoded = bytes.fromhex(content).decode('utf-8')
        except UnicodeDecodeError:
            try:
                # Try to decode to latin-1 if UTF-8 failed
                decoded = bytes.fromhex(content).decode('latin-1')
            except UnicodeDecodeError:
                # Somehow failed to decode the SMS content
                log.error(f'Failed to decode SMS content: {content}')
                # Fallback and return the raw content
                decoded = content

        # Strip null bytes from the decoded output
        return decoded.replace('\x00', '')

    def decode_sms_timestamp(self, timestamp: str) -> datetime:
        """
        Decode the SMS timestamp into a datetime object

        Args:
            timestamp (str): SMS timestamp (e.g. 23,09,09,10,44,00,-12)

        Returns:
            datetime: Datetime-parsed SMS timestamp
        """
        # Decode the timestamp into a tz-aware datetime object
        # YY:MM:DD:HH:MM:SS
        return datetime.strptime(timestamp[:-4], '%y,%m,%d,%H,%M,%S')

    def login(self, modem_ip: str, modem_pass: str):
        """
        Login to the ZTE modem and generate a session

        Args:
            modem_ip (str): ZTE modem IP address
            modem_pass (str): ZTE modem web interface password

        Raises:
            Exception: Thrown if the login fails
        """
        # Login payload for ZTE modem web interface
        payload = {
            'isTest': 'false',
            'goformId': 'LOGIN',
            'password': f'{b64encode(modem_pass.encode()).decode()}' # Base64 encoded password
        }
        headers = {
            'Host': f'{modem_ip}',
            'Referer': f'http://{modem_ip}/index.html',
            'X-Requested-With': 'XMLHttpRequest'
        }

        login_request = self.http.post(
            f'http://{modem_ip}/goform/goform_set_cmd_process',
            headers=headers,
            data=payload,
            timeout=30
        )

        # Response should be {"result":"0"} on login success
        if login_request.json()['result'] != '0':
            raise Exception('Login failed')

        # Cache the response cookies
        self.cookies = login_request.cookies

        # Fetch the modem firmware version and RD values
        # Needed for deleting SMS messages
        values = self.fetch_cmd_values(modem_ip, ['wa_inner_version'])
        self.wa_inner_version = values['wa_inner_version']

        log.debug(f'Logged in with stok {self.cookies["stok"]}, wa_inner_version {self.wa_inner_version}')

    def fetch_sms_inbox(self, modem_ip: str) -> list[dict]:
        """
        Fetch all SMS messages from the ZTE modem

        Args:
            modem_ip (str): ZTE modem IP address

        Returns:
            list[dict]: List of all SMS messages
        """
        # GET http://10.1.0.1/goform/goform_get_cmd_process?isTest=false&cmd=sms_data_total&page=0&data_per_page=500&mem_store=1&tags=10&order_by=order+by+id+desc&_=1694368424103
        url = f'http://{modem_ip}/goform/goform_get_cmd_process'
        params = {
            'isTest': False,
            'cmd': 'sms_data_total',
            'page': 0,
            'data_per_page': 500,
            'mem_store': 1,
            'tags': 10,
            'order_by': 'order by id desc'
        }
        headers = {
            'Host': f'{modem_ip}',
            'Referer': f'http://{modem_ip}/index.html',
            'X-Requested-With': 'XMLHttpRequest'
        }

        sms_request = self.http.get(
            url,
            params=params,
            headers=headers,
            cookies=self.cookies,
            timeout=30
        )

        return sms_request.json()['messages']
    
    def fetch_cmd_values(self, modem_ip: str, values: list) -> str:
        """
        Fetch the firmware version value from the modem
        """
        # http://10.1.0.1/goform/goform_get_cmd_process?isTest=false&cmd=Language%2Ccr_version%2Cwa_inner_version&multi_data=1&_=1700768732444
        url = f'http://{modem_ip}/goform/goform_get_cmd_process'
        params = {
            'isTest': False,
            'cmd': ','.join(values),
            'multi_data': 1
        }
        headers = {
            'Host': f'{modem_ip}',
            'Referer': f'http://{modem_ip}/index.html',
            'X-Requested-With': 'XMLHttpRequest'
        }
        request = self.http.get(
            url,
            params=params,
            headers=headers,
            cookies=self.cookies,
        )

        return request.json()

    def delete_sms(self, modem_ip: str, sms_id: str):
        """
        Delete an SMS message from the ZTE modem

        Args:
            modem_ip (str): ZTE modem IP address
            sms_id (int): SMS ID to delete
        """
        # No clue why these are required to delete SMS messages, but they are
        # MD5 hash wa_inner_version
        rd0_md5 = md5(self.wa_inner_version.encode()).hexdigest()
        # MD5 hash the rd0 hash and rd value
        rd = self.fetch_cmd_values(modem_ip, ['RD'])['RD']
        rd0_rd_md5 = md5(f'{rd0_md5}{rd}'.encode()).hexdigest()

        # POST http://10.1.0.1/goform/goform_set_cmd_process
        url = f'http://{modem_ip}/goform/goform_set_cmd_process'
        form = {
            'isTest': False,
            'goformId': 'DELETE_SMS',
            'msg_id': f'{sms_id};',
            'notCallback': True,
            'AD': rd0_rd_md5
        }
        headers = {
            'Host': f'{modem_ip}',
            'Referer': f'http://{modem_ip}/index.html',
            'X-Requested-With': 'XMLHttpRequest'
        }

        sms_request = self.http.post(
            url,
            headers=headers,
            cookies=self.cookies,
            data=form,
            timeout=30
        )

        try:
            # Check if the SMS was deleted successfully
            response = sms_request.json()
            if response['result'] != 'success':
                log.error(f'Failed to delete SMS {sms_id}: {response["result"]}')
        except Exception as e:
            log.error(f'Failed to delete SMS {sms_id}: {e}')


    def send_email(self, sender: str, recipient: str | list, subject: str, body: str, smtp_username: str, smtp_password: str, smtp_host: str, smtp_port: int, tls: bool):
        """
        Send an email via SMTP

        Args:
            sender (str): SMTP sender address
            recipient (str | list): Recipient address(es)
            subject (str): Email subject
            body (str): Email body
            smtp_username (str): SMTP username
            smtp_password (str): SMTP password
            smtp_host (str): SMTP host/IP
            smtp_port (int): SMTP port
            tls (bool): Use SMTP TLS
        """
        # Create an SMTP client
        smtp = SMTP(host=smtp_host, port=smtp_port)
        if tls:
            # Start TLS session
            smtp.starttls()
        # Login to the SMTP server
        smtp.login(smtp_username, smtp_password)
        # Send the email
        smtp.sendmail(sender, recipient, f'From: {sender}\nSubject: {subject}\n\n{body}')
        # Close the SMTP session
        smtp.quit()

    def run(self):
        # Login and fetch the initial SMS inbox list on the first run
        while True:
            try:
                log.info('Fetching initial SMS inbox list...')
                # Generate an initial session
                self.login(self.modem_ip, self.modem_password)
                # Fetch the initial SMS inbox list
                sms_inbox = self.fetch_sms_inbox(self.modem_ip)
                break
            except requests.exceptions.ConnectTimeout:
                log.warning('Initial login and fetch failed, retrying in 30 seconds')
                # Wait 30 seconds before retrying
                sleep(30)

        log.info('Fetched initial SMS inbox list, waiting for new messages')

        # Loop forever and check for new SMS messages
        while True:
            # Sleep for the SMS inbox fetch interval
            sleep(self.inbox_fetch_interval)

            # Fetch the latest SMS inbox list
            try:
                sms_inbox_latest = self.fetch_sms_inbox(self.modem_ip)
                # Check if the inbox list is empty
                if len(sms_inbox_latest) == 0:
                    log.debug('Got empty SMS inbox list, skipping')
                    continue
                elif len(sms_inbox_latest) < len(sms_inbox):
                    log.debug('Got smaller SMS inbox list than previous, fetching again to confirm')
                    raise KeyError
            except requests.exceptions.ConnectTimeout as e:
                log.warning(f'Failed to fetch SMS inbox: {e}')
                continue
            except KeyError:
                # Session most likely expired
                log.debug('Session expired, generate new session')
                # Generate a new session
                self.login(self.modem_ip, self.modem_password)
                # Try to fetch the latest SMS inbox list with the new session
                try:
                    sms_inbox_latest = self.fetch_sms_inbox(self.modem_ip)
                except requests.exceptions.ConnectTimeout as e:
                    log.error(f'Failed to fetch SMS inbox: {e}')
                    continue

            log.debug(f'Fetched latest SMS inbox list: {sms_inbox_latest}')

            sms_old = [f'{sms["number"]}{sms["content"]}{sms["date"]}' for sms in sms_inbox]
            sms_new = [(f'{sms["number"]}{sms["content"]}{sms["date"]}', sms) for sms in sms_inbox_latest]

            for sms in sms_new:
                if sms[0] not in sms_old:
                    # Get the full SMS object
                    sms = sms[1]

                    # Check if we should delete the SMS
                    if self.inbox_delete_sms:
                        # Delete the SMS
                        self.delete_sms(self.modem_ip, sms['id'])

                    # Decode the SMS content
                    content = self.decode_sms_content(sms['content'])
                    # Decode the SMS timestamp
                    timestamp = self.decode_sms_timestamp(sms['date'])
                    # Check if the SMS is older than a day
                    if (datetime.now() - timestamp).days > 1:
                        # Probably not actually a new SMS, skip it
                        log.debug(f'Skipping SMS from {sms["number"]} as it is older than a day')
                        continue

                    blacklist = False
                    # Run the SMS content through the blacklist
                    for word in self.blacklist['words']:
                        if word.search(content):
                            log.warning(f'Received blacklisted SMS: From: {sms["number"]}, Date: {timestamp.ctime()}, Blacklisted Word: {word.pattern}, Message: {content}')
                            blacklist = True
                            break
                    # Check if the SMS content is blacklisted
                    if blacklist:
                        continue

                    # Run the SMS number through the blacklist
                    for number in self.blacklist['numbers']:
                        if number.search(sms['number']):
                            log.warning(f'Received blacklisted SMS: From: {sms["number"]}, Date: {timestamp.ctime()}, Blacklisted Number: {number.pattern}, Message: {content}')
                            blacklist = True
                            break
                    # Check if the SMS number is blacklisted
                    if blacklist:
                        continue

                    log.info(f'Received SMS: From: {sms["number"]}, Date: {timestamp.ctime()}, Message: {content}')

                    # TODO: use a queue for this?
                    # Keep trying to send until it succeeds in case of network/server issues
                    while True:
                        try:
                            # Send an email with the SMS details
                            self.send_email(
                                sender=self.smtp_sender,
                                recipient=self.smtp_recipients,
                                subject=f'{self.smtp_subject_prefix}New SMS from {sms["number"]}',
                                body=f'From: {sms["number"]}\nDate: {timestamp.ctime()}\nMessage: {content}',
                                smtp_username=self.smtp_username,
                                smtp_password=self.smtp_password,
                                smtp_host=self.smtp_host,
                                smtp_port=self.smtp_port,
                                tls=self.smtp_tls
                            )
                            break
                        except TimeoutError:
                            log.warning('Failed to send email, SMTP timed out')
                            # Retry SMTP send after 15 seconds
                            sleep(15)

            # Update the SMS inbox list
            sms_inbox = sms_inbox_latest

sms = SMS()
sms.run()
