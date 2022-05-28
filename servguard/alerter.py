"""
The slack Webhook Module that is responsible for alerting the user incase of an incident

"""


from slack_sdk.webhook.async_client import AsyncWebhookClient
from servguard import logger
from servguard import log2sys
import asyncio

class Alert():

    def __init__(self,debug=False):

        self.logger=logger.ServGuardLogger(
            __name__,
            debug=debug
        )
        self.log2sys=log2sys.WafLogger(__name__,debug=debug)

        self.URL="https://hooks.slack.com/services/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"

    async  def send_alert(self,msg:dict):

        client=AsyncWebhookClient(self.URL)
        resp=await client.send(
            text="Incident Detected",
            blocks=[{
                "type": "section",
                "text":{
                    "type":"mrkdwn",
                    "text":"*Origin:* {}\n*IP:*  {}\n*Incident:*  {}".format(msg["Origin"],msg["IP"],msg["Incident"])
                }
            }]

        )
        try:
            assert resp.status_code==200
            assert resp.body=="ok"
            self.logger.log(
                "Slack Alert Sent Successfully",
                logtype="info"

            )
            self.log2sys.write_log("Slack Alert Sent Successfully")
        except AssertionError:
            self.logger.log(
                "Unable to Send Slack Alert",
                logtype="error"
            )
            self.log2sys.write_log("Unable to Send Slack Alert")
    def run(self,msg:dict):
        asyncio.run(self.send_alert(msg))

