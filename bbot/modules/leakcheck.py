from bbot.modules.base import BaseModule
from leakcheck import LeakCheckAPI

class leakcheck(BaseModule):
    """
    Resolve DNS_NAMEs
    """

    deps_pip = ["leakcheck"]
    watched_events = ["EMAIL_ADDRESS"]
    produced_events = ["FINDING"]
    flags = ["passive"]
    options = {"api_key": ""}
    options_desc = {"api_key": "Shodan API key"}
    
    def setup(self):
        super().setup()
        return self.require_api_key()

    def handle_event(self, event):
        api = LeakCheckAPI()
        api.set_key(self.api_key)
        result = api.lookup(event.data)
        try:
            line = result[0].get('line')
        except:
            return
        #rint(result)
        self.emit_event({"result":line}, "LEAK", source=event)
