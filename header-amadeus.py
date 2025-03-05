from burp import IBurpExtender, IHttpListener, IExtensionHelpers

class BurpExtender(IBurpExtender, IHttpListener):
    HEADER_NAME = "PYPentest"
    HEADER_VALUE = "" #Replace with value

    def registerExtenderCallbacks(self, callbacks):
        # Keep a reference to the callbacks object
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set the extension name
        callbacks.setExtensionName("Amadeus Whitelist Header")
        
        # Register this extension as an HTTP listener
        callbacks.registerHttpListener(self)
        
        # Log a message to show that the extension is loaded
        callbacks.issueAlert("Amadeus Whitelist Header Loaded - Omkar")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only modify outgoing requests
        if messageIsRequest:
            # Get the request info and headers
            request_info = self._helpers.analyzeRequest(messageInfo)
            headers = list(request_info.getHeaders())
            
            # Add or replace the custom header
            headers = [header for header in headers if not header.startswith("{}:".format(self.HEADER_NAME))]
            headers.append("{}: {}".format(self.HEADER_NAME, self.HEADER_VALUE))
            
            # Get the request body
            body_offset = request_info.getBodyOffset()
            request_bytes = messageInfo.getRequest()
            body = request_bytes[body_offset:]
            
            # Rebuild the request with the modified headers
            new_request = self._helpers.buildHttpMessage(headers, body)
            messageInfo.setRequest(new_request)
