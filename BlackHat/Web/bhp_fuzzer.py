import random
from burp import IBurpExtender
form burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from java.util import List, ArrayList

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        return

    def getGeneratorName(self):
        return "BHP Payload Generator"

    def createNewInstance(self, attack):
        return BHPFuzzer(self, attack)

class BHPFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.max_payloads = 10
        self.num_iterations = 0
        return

    def hasMorePayloads(self):
        if self.num_iterations == self.max_payloads:
            return False
        else:
            return True

    def getNextPayload(self,current_payload):
        # convert into string
        payload = "".join(chr(x) for x in current_payload)
        # call simple mutator to fuzz POST
        self.num_iterations +=1
        return payload

    def reset(self):
        self.num_iterations = 0
        return

    def mutate_payload(self,original_payload):
        # choose mutator or call external script
        picker = random.randint(1,3)

        # select a random offset in payload to mutate
        offset = random.randint(0,len(original_payload)-1)
        payload = original_payload[:offset]

        # random offset insert SQL inject attempt
        if picker == 1:
            payload += "'"

        # add XSS attempt
        if picker == 2:
            payload += "<script>alert('BHP!');,</script>"

        # repeat section of original payload randint
        if picker == 3:
            chunk_length = random.randint(len(payload[offset:]),len(payload)-1)
            repeater = random.randint(1,10)

            for i in range(repeater):
                payload += original_payload[offset:offset+chunk_length]

        # add remaining payload bits
        payload += original_payload[offset:]
        return payload