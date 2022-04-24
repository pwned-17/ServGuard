
from servguard import logger

try:
    # if Python 3.X.X
    from urllib.parse import urlparse
except ImportError:
    # if Python 2.X.X
    from urlparse import urlparse


class HeaderAnalyzer(object):
    """Class for Secure-Headers."""

    def __init__(self,headers,debug=True):
        """Initialize  class."""

        self.logger = logger.ServGuardLogger(
                __name__,
                debug=debug
        )
        self.headers=headers



    def find_insecure_headers(self):
        """
        Find insecure headers from the gathered headers.
        Working:
            Searches for the following insecure headers:
                1. X-XSS-Protection
                2. X-Content-Type
                3. Strict Transport Security
                4. Content Security Policy
                5. X-Frame
        Args:
            None
        Returns:
            None
        Raises:
            None
        """
        headers_dict = self.headers

        try:
            xss_protect = headers_dict['X-XSS-Protection']
            if xss_protect:
                if xss_protect != '1; mode=block':
                    self.logger.log(
                        "XSS Protection NOT set properly.",
                        logtype="warning"
                    )
                else:
                    self.logger.log(
                        "XSS Protection set properly.",
                        logtype="info"
                    )
        except KeyError:
            self.logger.log(
                "XSS Protection Not Enabled",
                logtype="warning"
            )
        except Exception as e:
            self.logger.log(
                "Error occured: " + str(e),
                logtype="error"
            )

        try:
            content_type = headers_dict['X-Content-Type-Options']
            if content_type:

                if content_type != 'nosniff':
                    self.logger.log(
                        "Content type NOT set properly.",
                        logtype="warning"
                    )
                else:
                    self.logger.log(
                        "Content type set properly.",
                        logtype="info"
                    )
        except KeyError:
            self.logger.log(
                " X-Content type not set",
                logtype="info"
            )
        except Exception as e:
            self.logger.log(
                "Error occured: " + str(e),
                logtype="error"
            )

        try:
            hsts = headers_dict['Strict-Transport-Security']
            if hsts:
                self.logger.log(
                    "Strict-Transport-Security set properly.",
                    logtype="info"
                )

            else:
                self.logger.log(
                 "Strict-Transport-Security NOT set",
                    logtype="warning"
                 )
        except Exception as e:
            self.logger.log(
                "Error occured: " + str(e),
                logtype="error"
            )

        try:
            csp = headers_dict['Content-Security-Policy']
            if csp:
                self.logger.log(
                    "Content-Security-Policy set properly.",
                    logtype="info"
                )
            else:
                self.logger.log(
                    "Content-Security-Policy NOT set.",
                    logtype="warning"
                )
        except Exception as e:
            self.logger.log(
                "Error occured: " + str(e),
                logtype="error"
            )

        try:
            x_frame = headers_dict['x-frame-options']
            if x_frame:
                self.logger.log(
                    "X-Frame set properly, safe from X-Frame",
                    logtype="info"
                )
            else:
                self.logger.log(
                    "X-Frame NOT set .",
                    logtype="warning"
                )
        except Exception as e:
            self.logger.log(
                "Error ocurred: " + str(e),
                logtype="error"
            )



    def analyze(self):


        # Test insecure headers
        self.find_insecure_headers()

