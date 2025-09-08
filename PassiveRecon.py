# -*- coding: utf-8 -*-
from burp import IBurpExtender, IScannerCheck, ITab, IHttpListener, IScanIssue, IMessageEditorTab, IMessageEditorTabFactory
from java.io import PrintWriter
from java.net import URL
from java.net import URLDecoder
from java.util import ArrayList
import re
import json
from urllib import unquote
from javax import swing
from java.awt import Font, Color
from java.awt import EventQueue
from java.lang import Runnable, Thread
from javax.swing import JFileChooser
from javax.swing.event import DocumentListener
from javax.swing import JTabbedPane, JPanel, JScrollPane, JTextArea, BoxLayout, JButton

# Runnable wrapper for Swing thread safety
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner
    def run(self):
        self.runner()

# Exclusion list
JSExclusionList = ['jquery', 'google-analytics', 'gpt.js']

# MIME types we will scan
TEXT_MIME_TYPES = [
    "text/",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "application/xml",
    "application/xhtml+xml"
]

class BurpExtender(IBurpExtender, IScannerCheck, ITab, IHttpListener, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("PassiveRecon")

        callbacks.issueAlert("PassiveRecon Passive Scanner + Live HTTP Listener enabled")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)  # Added for live scanning
        callbacks.registerMessageEditorTabFactory(self)  # Register Meta GraphQL tab

        self.fullLog = []
        self.seenLinks = set()
        self.graphqlQueries = []
        self.subdomains = []
        self.urls = []

        self.initUI()
        self.callbacks.addSuiteTab(self)

        self.appendLog("PassiveRecon loaded (live scan active).")

    def createNewInstance(self, controller, editable):
        return GraphQLRequestTab(self, controller, editable)

    def initUI(self):
        self.tab = JTabbedPane()
        
        # Main tab
        mainPanel = swing.JPanel()
        self.setupMainTab(mainPanel)
        self.tab.addTab("Main", mainPanel)
        
        # GraphQL tab
        graphqlPanel = swing.JPanel()
        self.setupGraphQLTab(graphqlPanel)
        self.tab.addTab("GraphQL", graphqlPanel)
        
        # Subdomains tab
        subdomainsPanel = swing.JPanel()
        self.setupSubdomainsTab(subdomainsPanel)
        self.tab.addTab("Subdomains", subdomainsPanel)
        
        # URLs tab
        urlsPanel = swing.JPanel()
        self.setupURLsTab(urlsPanel)
        self.tab.addTab("URLs", urlsPanel)


    def setupMainTab(self, panel):
        self.outputLabel = swing.JLabel("Results:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255, 102, 52))

        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.BOLD, 18))
        self.outputTxtArea.setLineWrap(True)
        self.outputTxtArea.setEditable(False)
        self.logPane.setViewportView(self.outputTxtArea)

        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export Log", actionPerformed=self.exportLog)
        self.parentFrm = swing.JFileChooser()
        self.inScopeCheckBox = swing.JCheckBox("Scan in-scope URLs only", actionPerformed=self.toggleInScope)
        self.inScopeOnly = False

        self.searchLabel = swing.JLabel("Search:")
        self.searchField = swing.JTextField(15)
        self.searchField.setFont(Font("Consolas", Font.PLAIN, 14))
        self.searchField.setMaximumSize(self.searchField.getPreferredSize())
        self.searchField.getDocument().addDocumentListener(self.SearchListener(self, "main"))

        layout = swing.GroupLayout(panel)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        panel.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addComponent(self.outputLabel)
            .addComponent(self.logPane)
            .addGroup(layout.createSequentialGroup()
                .addComponent(self.clearBtn)
                .addComponent(self.exportBtn))
            .addComponent(self.inScopeCheckBox)
            .addGroup(layout.createSequentialGroup()
                .addComponent(self.searchLabel)
                .addComponent(self.searchField))
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.outputLabel)
            .addComponent(self.logPane)
            .addGroup(layout.createParallelGroup()
                .addComponent(self.clearBtn)
                .addComponent(self.exportBtn))
            .addComponent(self.inScopeCheckBox)
            .addGroup(layout.createParallelGroup()
                .addComponent(self.searchLabel)
                .addComponent(self.searchField))
        )

    def setupGraphQLTab(self, panel):
        self.graphqlLabel = swing.JLabel("GraphQL Queries:")
        self.graphqlLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.graphqlLabel.setForeground(Color(0, 102, 204))

        self.graphqlPane = swing.JScrollPane()
        self.graphqlTxtArea = swing.JTextArea()
        self.graphqlTxtArea.setFont(Font("Consolas", Font.BOLD, 18))
        self.graphqlTxtArea.setLineWrap(True)
        self.graphqlTxtArea.setEditable(False)
        self.graphqlPane.setViewportView(self.graphqlTxtArea)

        self.clearGraphQLBtn = swing.JButton("Clear GraphQL", actionPerformed=self.clearGraphQL)
        self.exportGraphQLBtn = swing.JButton("Export GraphQL", actionPerformed=self.exportGraphQL)

        self.graphqlSearchLabel = swing.JLabel("Search:")
        self.graphqlSearchField = swing.JTextField(15)
        self.graphqlSearchField.setFont(Font("Consolas", Font.PLAIN, 14))
        self.graphqlSearchField.setMaximumSize(self.graphqlSearchField.getPreferredSize())
        self.graphqlSearchField.getDocument().addDocumentListener(self.SearchListener(self, "graphql"))

        layout = swing.GroupLayout(panel)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        panel.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addComponent(self.graphqlLabel)
            .addComponent(self.graphqlPane)
            .addGroup(layout.createSequentialGroup()
                .addComponent(self.clearGraphQLBtn)
                .addComponent(self.exportGraphQLBtn))
            .addGroup(layout.createSequentialGroup()
                .addComponent(self.graphqlSearchLabel)
                .addComponent(self.graphqlSearchField))
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.graphqlLabel)
            .addComponent(self.graphqlPane)
            .addGroup(layout.createParallelGroup()
                .addComponent(self.clearGraphQLBtn)
                .addComponent(self.exportGraphQLBtn))
            .addGroup(layout.createParallelGroup()
                .addComponent(self.graphqlSearchLabel)
                .addComponent(self.graphqlSearchField))
        )

    def setupSubdomainsTab(self, panel):
        self.subdomainsLabel = swing.JLabel("Subdomains:")
        self.subdomainsLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.subdomainsLabel.setForeground(Color(0, 153, 76))

        self.subdomainsPane = swing.JScrollPane()
        self.subdomainsTxtArea = swing.JTextArea()
        self.subdomainsTxtArea.setFont(Font("Consolas", Font.BOLD, 18))
        self.subdomainsTxtArea.setLineWrap(True)
        self.subdomainsTxtArea.setEditable(False)
        self.subdomainsPane.setViewportView(self.subdomainsTxtArea)

        self.clearSubdomainsBtn = swing.JButton("Clear Subdomains", actionPerformed=self.clearSubdomains)
        self.exportSubdomainsBtn = swing.JButton("Export Subdomains", actionPerformed=self.exportSubdomains)

        self.subdomainsSearchLabel = swing.JLabel("Search:")
        self.subdomainsSearchField = swing.JTextField(15)
        self.subdomainsSearchField.setFont(Font("Consolas", Font.PLAIN, 14))
        self.subdomainsSearchField.setMaximumSize(self.subdomainsSearchField.getPreferredSize())
        self.subdomainsSearchField.getDocument().addDocumentListener(self.SearchListener(self, "subdomains"))

        layout = swing.GroupLayout(panel)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        panel.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addComponent(self.subdomainsLabel)
            .addComponent(self.subdomainsPane)
            .addGroup(layout.createSequentialGroup()
                .addComponent(self.clearSubdomainsBtn)
                .addComponent(self.exportSubdomainsBtn))
            .addGroup(layout.createSequentialGroup()
                .addComponent(self.subdomainsSearchLabel)
                .addComponent(self.subdomainsSearchField))
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.subdomainsLabel)
            .addComponent(self.subdomainsPane)
            .addGroup(layout.createParallelGroup()
                .addComponent(self.clearSubdomainsBtn)
                .addComponent(self.exportSubdomainsBtn))
            .addGroup(layout.createParallelGroup()
                .addComponent(self.subdomainsSearchLabel)
                .addComponent(self.subdomainsSearchField))
        )

    def setupURLsTab(self, panel):
        self.urlsLabel = swing.JLabel("URLs:")
        self.urlsLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.urlsLabel.setForeground(Color(153, 0, 153))

        self.urlsPane = swing.JScrollPane()
        self.urlsTxtArea = swing.JTextArea()
        self.urlsTxtArea.setFont(Font("Consolas", Font.BOLD, 18))
        self.urlsTxtArea.setLineWrap(True)
        self.urlsTxtArea.setEditable(False)
        self.urlsPane.setViewportView(self.urlsTxtArea)

        self.clearURLsBtn = swing.JButton("Clear URLs", actionPerformed=self.clearURLs)
        self.exportURLsBtn = swing.JButton("Export URLs", actionPerformed=self.exportURLs)

        self.urlsSearchLabel = swing.JLabel("Search:")
        self.urlsSearchField = swing.JTextField(15)
        self.urlsSearchField.setFont(Font("Consolas", Font.PLAIN, 14))
        self.urlsSearchField.setMaximumSize(self.urlsSearchField.getPreferredSize())
        self.urlsSearchField.getDocument().addDocumentListener(self.SearchListener(self, "urls"))

        layout = swing.GroupLayout(panel)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        panel.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addComponent(self.urlsLabel)
            .addComponent(self.urlsPane)
            .addGroup(layout.createSequentialGroup()
                .addComponent(self.clearURLsBtn)
                .addComponent(self.exportURLsBtn))
            .addGroup(layout.createSequentialGroup()
                .addComponent(self.urlsSearchLabel)
                .addComponent(self.urlsSearchField))
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.urlsLabel)
            .addComponent(self.urlsPane)
            .addGroup(layout.createParallelGroup()
                .addComponent(self.clearURLsBtn)
                .addComponent(self.exportURLsBtn))
            .addGroup(layout.createParallelGroup()
                .addComponent(self.urlsSearchLabel)
                .addComponent(self.urlsSearchField))
        )


    def appendLog(self, text):
        self.fullLog.append(text)
        self.outputTxtArea.append(text + "\n")

    def appendGraphQL(self, text):
        self.graphqlQueries.append(text)
        self.graphqlTxtArea.append(text + "\n")

    def appendSubdomain(self, text):
        self.subdomains.append(text)
        self.subdomainsTxtArea.append(text + "\n")

    def appendURL(self, text):
        self.urls.append(text)
        self.urlsTxtArea.append(text + "\n")


    class SearchListener(DocumentListener):
        def __init__(self, extender, tab_type):
            self.extender = extender
            self.tab_type = tab_type
            
        def insertUpdate(self, e): self.filterContent()
        def removeUpdate(self, e): self.filterContent()
        def changedUpdate(self, e): self.filterContent()
        
        def filterContent(self):
            if self.tab_type == "main":
                query = self.extender.searchField.getText().lower()
                self.extender.outputTxtArea.setText("")
                for line in self.extender.fullLog:
                    if query in line.lower():
                        self.extender.outputTxtArea.append(line + "\n")
            elif self.tab_type == "graphql":
                query = self.extender.graphqlSearchField.getText().lower()
                self.extender.graphqlTxtArea.setText("")
                for line in self.extender.graphqlQueries:
                    if query in line.lower():
                        self.extender.graphqlTxtArea.append(line + "\n")
            elif self.tab_type == "subdomains":
                query = self.extender.subdomainsSearchField.getText().lower()
                self.extender.subdomainsTxtArea.setText("")
                for line in self.extender.subdomains:
                    if query in line.lower():
                        self.extender.subdomainsTxtArea.append(line + "\n")
            elif self.tab_type == "urls":
                query = self.extender.urlsSearchField.getText().lower()
                self.extender.urlsTxtArea.setText("")
                for line in self.extender.urls:
                    if query in line.lower():
                        self.extender.urlsTxtArea.append(line + "\n")

    def getTabCaption(self):
        return "PassiveRecon"

    def getUiComponent(self):
        return self.tab

    def toggleInScope(self, event):
        self.inScopeOnly = not self.inScopeOnly
        self.appendLog("[+] Scan In-Scope URLs Only: " + str(self.inScopeOnly))

    def clearLog(self, event):
        self.outputTxtArea.setText("PassiveRecon loaded.\n")
        self.fullLog = ["PassiveRecon loaded."]
        self.seenLinks.clear()

    def clearGraphQL(self, event):
        self.graphqlTxtArea.setText("")
        self.graphqlQueries = []

    def clearSubdomains(self, event):
        self.subdomainsTxtArea.setText("")
        self.subdomains = []

    def clearURLs(self, event):
        self.urlsTxtArea.setText("")
        self.urls = []


    def exportLog(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        if ret == JFileChooser.APPROVE_OPTION:
            filename = chooseFile.getSelectedFile().getCanonicalPath()
            with open(filename, 'w') as f:
                f.write("\n".join(self.fullLog))

    def exportGraphQL(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.graphqlPane, "Choose file")
        if ret == JFileChooser.APPROVE_OPTION:
            filename = chooseFile.getSelectedFile().getCanonicalPath()
            with open(filename, 'w') as f:
                f.write("\n".join(self.graphqlQueries))

    def exportSubdomains(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.subdomainsPane, "Choose file")
        if ret == JFileChooser.APPROVE_OPTION:
            filename = chooseFile.getSelectedFile().getCanonicalPath()
            with open(filename, 'w') as f:
                f.write("\n".join(self.subdomains))

    def exportURLs(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.urlsPane, "Choose file")
        if ret == JFileChooser.APPROVE_OPTION:
            filename = chooseFile.getSelectedFile().getCanonicalPath()
            with open(filename, 'w') as f:
                f.write("\n".join(self.urls))




    def is_text_based(self, ihrr):
        try:
            # can accept either IHttpRequestResponse or message bytes; handle gracefully
            resp = ihrr.getResponse()
            if resp is None:
                return False
            headers = self.helpers.analyzeResponse(resp).getHeaders()
            for header in headers:
                if header.lower().startswith("content-type:"):
                    ctype = header.split(":", 1)[1].strip().lower()
                    return any(ctype.startswith(mt) for mt in TEXT_MIME_TYPES)
        except:
            pass
        return False

    def scanJS(self, ihrr):
        try:
            if ihrr.getResponse() is None:
                return None
            linkA = linkAnalyse(ihrr, self.helpers)
            return linkA.analyseURL()
        except UnicodeEncodeError:
            return None

    def doPassiveScan(self, ihrr):
        try:
            urlReq = ihrr.getUrl()
            if self.inScopeOnly and not self.callbacks.isInScope(urlReq):
                return None
            if not self.is_text_based(ihrr):
                return None
            if any(x in str(urlReq) for x in JSExclusionList):
                return None
            if str(urlReq) in self.seenLinks:
                return None
            self.appendLog("[+] Valid URL found: " + str(urlReq))
            self.seenLinks.add(str(urlReq))
            linkA = linkAnalyse(ihrr, self.helpers)
            issueText = linkA.analyseURL()
            for counter, issue in enumerate(issueText):
                link = issue['link']
                if link not in self.seenLinks:
                    self.appendLog("\t" + str(counter) + ' - ' + link)
                    self.seenLinks.add(link)
            
            # Extract GraphQL queries, subdomains, URLs
            self.extractGraphQL(ihrr)
            self.extractSubdomains(ihrr)
            self.extractURLs(ihrr)
            
            issues = ArrayList()
            issues.add(SRI(ihrr, self.helpers))
            return issues
        except UnicodeEncodeError:
            return None
        except Exception as e:
            self.appendLog("[!] Passive scan error: " + str(e))
            return None

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Live listener for all HTTP messages.
        """
        try:
            urlReq = messageInfo.getUrl()
            
            # Respect in-scope filter
            if urlReq and self.inScopeOnly and not self.callbacks.isInScope(urlReq):
                return

            self.extractGraphQL(messageInfo)
            
            # For responses only, do additional processing
            if not messageIsRequest:
                if urlReq and any(x in str(urlReq) for x in JSExclusionList):
                    return
                
                if urlReq and str(urlReq) in self.seenLinks:
                    return
                    
                if urlReq:
                    self.appendLog("[+] URL found: " + str(urlReq))
                    self.seenLinks.add(str(urlReq))

                issueText = self.scanJS(messageInfo)
                if issueText:
                    for counter, issue in enumerate(issueText):
                        link = issue['link']
                        if link not in self.seenLinks:
                            self.appendLog("\t" + str(counter) + ' - ' + link)
                            self.seenLinks.add(link)
                
                # Additional extraction for responses
                self.extractSubdomains(messageInfo)
                self.extractURLs(messageInfo)

        except Exception as e:
            self.appendLog("[!] Live scan error: " + str(e))
            
    def extractValue(self, body, key):
        """Helper method to extract values from request body (from your second extension)"""
        start = body.find(key) + len(key) + 1
        end = body.find("&", start)
        if end == -1:
            end = len(body)
        return body[start:end]


    def extractGraphQL(self, ihrr):
        try:
            # Get both request and response
            request_info = None
            response_body = None
            request_body = ""
            
            # Extract request information (Meta GraphQL parsing)
            try:
                request_bytes = ihrr.getRequest()
                if request_bytes:
                    request_info = self.helpers.analyzeRequest(request_bytes)
                    request_headers = request_info.getHeaders()
                    request_body = self.helpers.bytesToString(request_bytes[request_info.getBodyOffset():])
                    
                    # Meta GraphQL detection from your second extension
                    meta_graphql_detected = False
                    meta_graphql_info = ""
                    
                    # Check for Facebook-style GraphQL patterns
                    if "fb_api_req_friendly_name" in request_body:
                        meta_graphql_detected = True
                        meta_graphql_info += "Friendly Name: " + self.extractValue(request_body, "fb_api_req_friendly_name") + "\n"
                    
                    # Check for variables
                    if "variables" in request_body:
                        meta_graphql_detected = True
                        variables = self.extractValue(request_body, "variables")
                        try:
                            decoded_vars = unquote(variables)
                            pretty_vars = json.dumps(json.loads(decoded_vars), indent=2)
                            meta_graphql_info += "Variables:\n" + pretty_vars + "\n"
                        except:
                            meta_graphql_info += "Variables (raw): " + variables + "\n"
                    
                    # Check for doc_id
                    if "doc_id" in request_body:
                        meta_graphql_detected = True
                        meta_graphql_info += "Document ID: " + self.extractValue(request_body, "doc_id") + "\n"
                    
                    if meta_graphql_detected:
                        graphql_entry = "=== GRAPHQL REQUEST ===\n"
                        graphql_entry += "URL: " + str(ihrr.getUrl()) + "\n"
                        graphql_entry += meta_graphql_info + "-"*50 + "\n"
                        
                        if graphql_entry not in self.graphqlQueries:
                            self.appendGraphQL(graphql_entry)
                            
            except Exception as e:
                self.appendLog("[!] Error in Meta GraphQL request parsing: " + str(e))
            
            # Extract response information (traditional GraphQL patterns)
            if ihrr.getResponse() is not None:
                response_body = self.helpers.bytesToString(ihrr.getResponse())
                
                # Traditional GraphQL patterns in response
                graphql_query_regex = r"\bquery\s+\w+\s*[\{\(][^,]*\}"
                graphql_mutation_regex = r"\bmutation\s+\w+\s*[\{\(][^,]*\}"
                graphql_fragment_regex = r"\bfragment\s[^\",]*\}"
                
                queries = re.findall(graphql_query_regex, response_body, re.IGNORECASE | re.DOTALL)
                mutations = re.findall(graphql_mutation_regex, response_body, re.IGNORECASE | re.DOTALL)
                fragments = re.findall(graphql_fragment_regex, response_body, re.IGNORECASE | re.DOTALL)
                
                if queries or mutations or fragments:
                    graphql_entry = "=== GRAPHQL RESPONSE CONTENT ===\n"
                    graphql_entry += "URL: " + str(ihrr.getUrl()) + "\n"
                    
                    for query in queries:
                        graphql_entry += "Query found:\n" + query + "\n" + "-"*50 + "\n"
                        
                    for mutation in mutations:
                        graphql_entry += "Mutation found:\n" + mutation + "\n" + "-"*50 + "\n"

                    for fragment in fragments:
                        graphql_entry += "Fragment found:\n" + fragment + "\n" + "-"*50 + "\n"
                    
                    if graphql_entry not in self.graphqlQueries:
                        self.appendGraphQL(graphql_entry)
                        
        except Exception as e:
            self.appendLog("[!] Error extracting GraphQL: " + str(e))



    def extractValue(self, body, key):
        """Helper method to extract values from request body"""
        start = body.find(key) + len(key) + 1
        end = body.find("&", start)
        if end == -1:
            end = len(body)
        return body[start:end]

    def extractSubdomains(self, ihrr):
        try:
            if ihrr.getResponse() is None:
                return    
            body = self.helpers.bytesToString(ihrr.getResponse())
            url = ihrr.getUrl().toString()
            domain = URL(url).getHost()
            
            # Extract subdomains from the response body
            subdomain_regex = r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|gov|edu|co|in|us|uk|info|biz|me|online|dev|app|cloud|tech|ai|xyz|pro)(?::\d{1,5})?\b"
            subdomains = re.findall(subdomain_regex, body, re.IGNORECASE)
            
            for subdomain in subdomains:
                if subdomain != domain and subdomain not in self.subdomains:
                    self.appendSubdomain(subdomain)
                    
        except Exception as e:
            self.appendLog("[!] Error extracting subdomains: " + str(e))

    def extractURLs(self, ihrr):
        try:
            if ihrr.getResponse() is None:
                return
            body = self.helpers.bytesToString(ihrr.getResponse())
            
            # URL regex pattern
            url_regex = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[/\w\.-=&%]*"
            urls = re.findall(url_regex, body, re.IGNORECASE)
            
            for url in urls:
                if url not in self.urls:
                    self.appendURL(url)
                    
        except Exception as e:
            self.appendLog("[!] Error extracting URLs: " + str(e))


    def consolidateDuplicateIssues(self, isb, isa):
        return -1

class linkAnalyse():
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres

    regex_str = r"""
    (?:"|'|`)
    (
        ((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})
        |
        ((?:/|\.\./)?[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})
        |
        (?:\${?[a-zA-Z]+}?|/)(?:/\${?[a-zA-Z0-9_]+})*[a-zA-Z0-9_\-/]+(?::[a-zA-Z]+)?(?:/[a-zA-Z0-9_\-/]*)*(?:\.(?:[a-zA-Z]{1,4}|action))?
        |
        ([a-zA-Z0-9_\-/]+/[a-zA-Z0-9_\-/]+\.(?:[a-zA-Z]{1,4}|action)(?:[\?|/][^"|']{0,}|))
        |
        ([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"|']{0,}|))
    )
    (?:"|'|`)
    """

    def analyseURL(self):
        issueLinks = []
        try:
            if self.reqres.getResponse() is None:
                return issueLinks
            body = self.helpers.bytesToString(self.reqres.getResponse())
            links = re.findall(self.regex_str, body, re.VERBOSE)
            for link in links:
                link_str = link[0] if isinstance(link, tuple) else link
                if '/' in link_str and ' ' not in link_str and ',' not in link_str and not link_str.startswith('./') and not link_str.startswith('}') and not link_str.startswith('=') and not link_str.startswith('@') and not link_str.startswith('../') and self.is_valid_link(link_str):
                    issueLinks.append({'link': link_str})
            return issueLinks
        except:
            return None

    def is_valid_link(self, link):
        if re.search(r'[^\x20-\x7E]', link):
            return False
        if len(link) > 2048:
            return False
        return True

class SRI(IScanIssue):
    def __init__(self, reqres, helpers):
        self.reqres = reqres
        self.helpers = helpers

    def getIssueType(self):
        return "JavaScript Link Analysis"
    def getSeverity(self):
        return "Informational"
    def getConfidence(self):
        return "Certain"
    def getIssueDetail(self):
        return "This text-based file has been analyzed."
    def getRemediationDetail(self):
        return "No remediation required."
    def getHttpMessages(self):
        return [self.reqres]
    def getIssueName(self):
        return "Text-based URL Found"
    def getUrl(self):
        return self.reqres.getUrl()

class GraphQLRequestTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender.helpers
        self._editable = editable
        self._modified = False  # Track modification state

        # Use Burp Suite's built-in message editor
        self._editor = extender.callbacks.createMessageEditor(controller, editable)

        # Create panel UI
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))
        self._scanButton = JButton("Scan", actionPerformed=self.scanRequest)
        self._panel.add(self._editor.getComponent())
        self._panel.add(self._scanButton)

        self._currentMessage = None
        self._currentRequestInfo = None
        self._responseTab = None
        self._tabbedPane = None

    def getTabCaption(self):
        return "Meta GraphQL"

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        if isRequest:
            try:
                request_info = self._helpers.analyzeRequest(content)
                headers = request_info.getHeaders()
                body = content[request_info.getBodyOffset():].tostring()
                return "graphql" in headers[0].lower() and (
                    "fb_api_req_friendly_name" in body
                    or "variables" in body
                    or "doc_id" in body
                )
            except:
                return False
        return False

    def setMessage(self, content, isRequest):
        self._modified = False  # Reset modified state when new message is set
        if content is None:
            self._editor.setMessage(None, isRequest)
        else:
            if isRequest:
                self._currentMessage = content
                self._currentRequestInfo = self._helpers.analyzeRequest(content)
                body = content[self._currentRequestInfo.getBodyOffset():].tostring()
                parsed_body = self.parseGraphQLBody(body)
                self._editor.setMessage(self._helpers.stringToBytes(parsed_body), isRequest)
            else:
                self._editor.setMessage(None, isRequest)

    # NEW: Required method - check if content has been modified
    def getMessage(self):
        if self._editor.isMessageModified():
            return self._editor.getMessage()
        return self._currentMessage

    def isModified(self):
        return self._editor.isMessageModified()

    def getSelectedData(self):
        return self._editor.getSelectedData()


    def parseGraphQLBody(self, body):
        parsed_output = []

        if "fb_api_req_friendly_name" in body:
            parsed_output.append("fb_api_req_friendly_name: " +
                                 self.extractValue(body, "fb_api_req_friendly_name"))

        if "variables" in body:
            variables = self.extractValue(body, "variables")
            decoded_variables = unquote(variables)
            try:
                pretty_json = json.dumps(json.loads(decoded_variables), indent=4, ensure_ascii=False)
                parsed_output.append("variables:\n" + pretty_json)
            except:
                parsed_output.append("variables (raw): " + decoded_variables)

        if "doc_id" in body:
            parsed_output.append("doc_id: " + self.extractValue(body, "doc_id"))

        return "\n".join(parsed_output)

    def extractValue(self, body, key):
        start = body.find(key) + len(key) + 1
        end = body.find("&", start)
        if end == -1:
            end = len(body)
        return body[start:end]

    def scanRequest(self, event):
        if self._currentMessage is not None and self._currentRequestInfo is not None:
            try:
                modified_body = self._editor.getMessage()
                headers = self._currentRequestInfo.getHeaders()
                new_request = self._helpers.buildHttpMessage(headers, modified_body)
                http_service = self._currentMessage.getHttpService()
                response = self._extender.callbacks.makeHttpRequest(http_service, new_request)
                self.displayResponse(response)
            except:
                pass

    def displayResponse(self, response):
        if self._responseTab is None:
            self._responseTab = self._extender.callbacks.createMessageEditor(None, False)
            self._responsePanel = JPanel()
            self._responsePanel.setLayout(BoxLayout(self._responsePanel, BoxLayout.Y_AXIS))
            self._responsePanel.add(self._responseTab.getComponent())
            self._tabbedPane = JTabbedPane()
            self._tabbedPane.addTab("Meta GraphQL", self._panel)
            self._tabbedPane.addTab("GraphQL Response", self._responsePanel)
            self._panel.getParent().add(self._tabbedPane)
            self._panel.getParent().revalidate()

        self._responseTab.setMessage(response.getResponse(), False)