import colorlog
import logging
import os
import requests
import sys

from base64 import b64encode
from datetime import datetime
from smtplib import SMTP
from time import sleep


log = logging.getLogger('SMS')


class SMS:
    def __init__(self):
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

        try:
            self.inbox_fetch_interval = int(os.environ.get('MODEM_SMS_INBOX_FETCH_INTERVAL', 30))
        except ValueError:
            log.exception('Invalid MODEM_SMS_INBOX_FETCH_INTERVAL environment variable, must be a number')
            exit(1)

    def login(self, modem_ip: str, modem_pass: str) -> requests.cookies.RequestsCookieJar:
        """
        Login to the ZTE modem and generate a session cookie

        Args:
            modem_ip (str): ZTE modem IP address
            modem_pass (str): ZTE modem web interface password

        Raises:
            Exception: Thrown if the login fails

        Returns:
            requests.cookies.RequestsCookieJar: Cookie jar containing a session cookie
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
        cookies = login_request.cookies

        return cookies

    def fetch_sms_inbox(self, modem_ip: str, cookies: requests.cookies.RequestsCookieJar) -> list[dict]:
        """
        Fetch all SMS messages from the ZTE modem

        Args:
            modem_ip (str): ZTE modem IP address
            cookies (requests.cookies.RequestsCookieJar): Cookie jar containing a session cookie

        Returns:
            list[dict]: List of all SMS messages
        """
        # http://10.1.0.1/goform/goform_get_cmd_process?isTest=false&cmd=sms_data_total&page=0&data_per_page=500&mem_store=1&tags=10&order_by=order+by+id+desc&_=1694368424103
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
            cookies=cookies,
            timeout=30
        )

        return sms_request.json()['messages']

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
        # Setup logging
        self._setup_logging()
        # Load environment variables
        self._load_env_vars()

        # Login and fetch the initial SMS inbox list on the first run
        while True:
            try:
                log.info('Fetching initial SMS inbox list...')
                # Generate the initial session cookie
                cookie = self.login(self.modem_ip, self.modem_password)
                # Fetch the initial SMS inbox list
                sms_inbox = self.fetch_sms_inbox(self.modem_ip, cookie)
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
                sms_inbox_latest = self.fetch_sms_inbox(self.modem_ip, cookie)
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
                # Session cookie most likely expired
                log.debug('Session cookie expired, generate new session')
                # Generate a new session cookie
                cookie = self.login(self.modem_ip, self.modem_password)
                # Try to fetch the latest SMS inbox list with the new session cookie
                try:
                    sms_inbox_latest = self.fetch_sms_inbox(self.modem_ip, cookie)
                except requests.exceptions.ConnectTimeout as e:
                    log.error(f'Failed to fetch SMS inbox: {e}')
                    continue

            log.debug(f'Fetched latest SMS inbox list: {sms_inbox_latest}')

            # Check if the latest SMS inbox list is different from the previous one
            if sms_inbox_latest != sms_inbox:
                # Get the difference between the two lists
                sms_new = [sms for sms in sms_inbox_latest if sms not in sms_inbox]
                log.debug(f'Got new SMS messages: {sms_new}')
                # Update the previous SMS inbox list
                sms_inbox = sms_inbox_latest

                # Loop through all new SMS messages
                for sms in sms_new:
                    # Decode the SMS content
                    content = self.decode_sms_content(sms['content'])
                    # Decode the SMS timestamp
                    timestamp = self.decode_sms_timestamp(sms['date'])
                    # Check if the SMS is older than a day
                    if (datetime.now() - timestamp).days > 1:
                        # Probably not actually a new SMS, skip it
                        log.debug(f'Skipping SMS from {sms["number"]} as it is older than a day')
                        continue

                    log.info(f'Received new SMS: From: {sms["number"]}, Date: {timestamp.ctime()}, Message: {content}')

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

sms = SMS()
sms.run()
