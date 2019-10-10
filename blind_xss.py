from burp import IBurpExtender, IScannerCheck
from burp import ITab
from burp import IHttpListener
from burp import IInterceptedProxyMessage
from burp import IMessageEditorController
from burp import IContextMenuFactory, IContextMenuInvocation
from javax.swing import (JLabel, JTextField, JOptionPane,
    JTabbedPane, JPanel, JButton, JMenu, JMenuItem, JTable, JScrollPane,
    JCheckBox, BorderFactory, Box, JFileChooser, ListSelectionModel)
from javax.swing.border import EmptyBorder
from java.awt import (GridBagLayout, Dimension, GridBagConstraints,
    Color, FlowLayout, BorderLayout, Insets)
from java.net import URL
from javax import swing
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table import AbstractTableModel, DefaultTableModel
from javax.swing.event import TableModelEvent, TableModelListener
from StringIO import StringIO
import os
import re
import threading
import random
import math
from java.lang import Runnable
from threading import Thread
from java.util import ArrayList, Arrays
import config


class MyTableModelListener(TableModelListener):
    def __init__(self, table, burp, data_dict, file):
        self.table = table
        self.burp = burp
        self.data_dict = data_dict
        self.file = file

    def tableChanged(self, e):
        if e.getType() == 1:
            data = self.table.getDataVector()
            value = data[-1][1]
            key = data[-1][0]
            if key == '':
                return
            if key[-1] == '\n':
                key = key[:-1]
            self.data_dict[key] = value
        if e.getType() == 0:
            for x in self.table.getDataVector():
                key = x[0]
                val = x[1]
                if key == '':
                    continue
                if key[-1] == '\n':
                    key = key[:-1]
                self.data_dict[key] = val
            try:
                self.data_dict.pop('')
            except Exception:
                pass
            self.burp.saveToFileAsync(self.file, self.data_dict)
        if e.getType() == -1:
            return
        try:
            self.data_dict.pop('')
        except Exception:
            pass


class PyRunnable(Runnable):
    """This class is used to wrap a python callable object into a Java Runnable that is 
       suitable to be passed to various Java methods that perform callbacks.
    """
    def __init__(self, target, *args, **kwargs):
        """Creates a PyRunnable.
           target - The callable object that will be called when this is run.
           *args - Variable positional arguments
           **wkargs - Variable keywoard arguments.
        """
        self.target = target
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        self.target(*self.args, **self.kwargs)


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory, IScannerCheck):
    name = "Femida XSS"
    conf_path = "./config.py"
    _jTabbedPane = JTabbedPane()
    _jPanel = JPanel()
    _jAboutPanel = JPanel()
    _jPanelConstraints = GridBagConstraints()
    _jLabelParameters = None
    _jTextFieldParameters = None
    _jLabelTechniques = None
    _jTextFieldURL = None
    _jLabelFuzzFactor = None
    _jTextFieldFuzzFactor = None
    _jLabelAdditionalCmdLine = None
    _jTextFieldAdditionalCmdLine = None
    _jButtonSetCommandLine = None
    _jLabelAbout = None
    _overwriteHeader = False
    _overwriteParam = False
    _forkRequestParam = False
    _JCheckBox_scope = None


    def doActiveScan(self, baseRequestResponse, insertionPoint):
        scan_issues = []
        try:
            requestString = str(baseRequestResponse.getRequest().tostring())
            newRequestString = self.prepareRequest(requestString)

            vulnerable, verifyingRequestResponse = self.quickCheckScan(newRequestString, baseRequestResponse)

        except Exception as msg:
            print(msg)

        return []


    def quickCheckScan(self, preparedRequest, requestResponse):
        check = self._callbacks.makeHttpRequest(requestResponse.getHttpService(), self._helpers.stringToBytes(preparedRequest))
        vulner = self._helpers.analyzeResponse(check.getResponse()).getStatusCode() == 200
        return vulner, check


    #
    # implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName(self.name)
        self._callbacks.registerScannerCheck(self)

        self._dictPayloads = {}
        self._dictHeaders = {}
        self._dictParams = {}
        self.status_flag = False
        self.scope_flag = False

        ### Scope button ###
        self._JCheckBox_scope = swing.JButton("In Scope only",  actionPerformed=self.active_scope)
        self._JCheckBox_scope.setBackground(Color.WHITE)
        self.createAnyView(self._JCheckBox_scope, 0, 0, 3, 1, Insets(0, 0, 10, 0))
        ####################

        self.jfc = JFileChooser("./")
        self.jfc.setDialogTitle("Upload Payloads")
        self.jfc.setFileFilter(FileNameExtensionFilter("TXT file", ["txt"]))

        self._layout = GridBagLayout()
        self._jPanel.setLayout(self._layout)

        self._jLabelTechniques = JLabel("Press to start:")
        self.createAnyView(self._jLabelTechniques, 3, 0, 3, 1, Insets(0, 0, 10, 0))

        self.submitSearchButton = swing.JButton('Run proxy', actionPerformed=self.active_flag)
        self.submitSearchButton.setBackground(Color.WHITE)
        self.createAnyView(self.submitSearchButton, 6, 0, 6, 1, Insets(0, 0, 10, 0))

        self._jPanel.setBounds(0, 0, 1000, 1000)
        self._jLabelTechniques = JLabel("Your URL (my.burpcollaborator.net):")
        self.createAnyView(self._jLabelTechniques, 0, 1, 3, 1, Insets(0, 0, 10, 0))

        self._jTextFieldURL = JTextField("", 30)
        self._jTextFieldURL.addActionListener(self.setCallbackUrl)
        self.createAnyView(self._jTextFieldURL, 3, 1, 5, 1, Insets(0, 0, 10, 0))

        self._forkRequestButton = swing.JButton('Parallel Request',actionPerformed=self.forkRequest)
        self._forkRequestButton.setBackground(Color.WHITE)
        self.createAnyView(self._forkRequestButton, 8, 1, 1, 1, Insets(0, 0, 10, 0))

        ### Filter extensions block ###
        self._jLabelExt = JLabel("Filtered extensions:")
        self.createAnyView(self._jLabelExt, 0, 2, 3, 1, Insets(0, 0, 10, 0))

        self._jTextFieldExt = JTextField("", 30)
        self._jTextFieldExt.addActionListener(self.setCallbackExt)
        self.createAnyView(self._jTextFieldExt, 3, 2, 10, 1, Insets(0, 0, 10, 0))
        ##############################

        self._tableModelPayloads = DefaultTableModel()
        self._tableModelPayloads.addColumn("Payload")
        self._tableModelPayloads.addColumn("Active")

        self._tableModelHeaders = DefaultTableModel()
        self._tableModelHeaders.addColumn("Header")
        self._tableModelHeaders.addColumn("Active")

        self._tableModelParams = DefaultTableModel()
        self._tableModelParams.addColumn("Parameter")
        self._tableModelParams.addColumn("Active")

        self._payloadTable = self.createAnyTable(self._tableModelPayloads, 1, Dimension(300, 200))
        self.createAnyView(self._payloadTable, 0, 3, 3, 1, Insets(0, 0, 0, 10))

        self._headerTable = self.createAnyTable(self._tableModelHeaders, 2, Dimension(300, 200))
        self.createAnyView(self._headerTable, 3, 3, 3, 1, Insets(0, 0, 0, 10))

        self._paramTable = self.createAnyTable(self._tableModelParams, 3, Dimension(300, 200))
        self.createAnyView(self._paramTable, 6, 3, 3, 1, Insets(0, 0, 0, 0))

        deletePayloadButton = swing.JButton('Delete',actionPerformed=self.deleteToPayload)
        deletePayloadButton.setBackground(Color.WHITE)
        self.createAnyView(deletePayloadButton, 0, 4, 1, 1, Insets(3, 0, 0, 0))

        deletePayloadButton = swing.JButton('Upload',actionPerformed=self.uploadToPayload)
        deletePayloadButton.setBackground(Color.WHITE)
        self.createAnyView(deletePayloadButton, 1, 4, 1, 1, Insets(3, 0, 0, 0))

        addPayloadButton = swing.JButton('Add',actionPerformed=self.addToPayload)
        addPayloadButton.setBackground(Color.WHITE)
        self.createAnyView(addPayloadButton, 2, 4, 1, 1, Insets(3, 0, 0, 10))

        deleteHeaderButton = swing.JButton('Delete',actionPerformed=self.deleteToHeader)
        deleteHeaderButton.setBackground(Color.WHITE)
        self.createAnyView(deleteHeaderButton, 3, 4, 1, 1, Insets(3, 0, 0, 0))

        self._overwriteHeaderButton = swing.JButton('Overwrite',actionPerformed=self.overwriteHeader)
        self._overwriteHeaderButton.setBackground(Color.WHITE)
        self.createAnyView(self._overwriteHeaderButton, 4, 4, 1, 1, Insets(3, 0, 0, 0))

        addHeaderButton = swing.JButton('Add',actionPerformed=self.addToHeader)
        addHeaderButton.setBackground(Color.WHITE)
        self.createAnyView(addHeaderButton, 5, 4, 1, 1, Insets(3, 0, 0, 10))

        deleteParamsButton = swing.JButton('Delete',actionPerformed=self.deleteToParams)
        deleteParamsButton.setBackground(Color.WHITE)
        self.createAnyView(deleteParamsButton, 6, 4, 1, 1, Insets(3, 0, 0, 0))

        self._overwriteParamButton = swing.JButton('Overwrite',actionPerformed=self.overwriteParam)
        self._overwriteParamButton.setBackground(Color.WHITE)
        self.createAnyView(self._overwriteParamButton, 7, 4, 1, 1, Insets(3, 0, 0, 0))

        addParamsButton = swing.JButton('Add',actionPerformed=self.addToParams)
        addParamsButton.setBackground(Color.WHITE)
        self.createAnyView(addParamsButton, 8, 4, 1, 1, Insets(3, 0, 0, 0))
        
        self._resultsTextArea = swing.JTextArea()
        resultsOutput = swing.JScrollPane(self._resultsTextArea)
        resultsOutput.setMinimumSize(Dimension(800,200))
        self.createAnyView(resultsOutput, 0, 5, 9, 1, Insets(10, 0, 0, 0))

        self.clearSearchButton = swing.JButton('Clear Search Output',actionPerformed=self.clearOutput)
        self.createAnyView(self.clearSearchButton, 3, 7, 3, 1, Insets(3, 0, 0, 0))

        self._callbacks.customizeUiComponent(self._jPanel)
        self._callbacks.addSuiteTab(self)
        self.starterPack()

        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)

        return


    def createAnyTable(self, table_model, table_number, min_size):
        _table = JTable(table_model)
        _table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        for i in range(2):
            column = _table.getColumnModel().getColumn(i)
            if i == 0:
                column.setPreferredWidth(250)
            else:
                column.setPreferredWidth(50)

        _scrolltable = JScrollPane(_table)
        _scrolltable.setMinimumSize(min_size)
        return _scrolltable


    def insertAnyTable(self, table, data):
        def detectTable(table):
            name = table.getColumnName(0)
            if name == 'Payloads':
                return 0
            elif name == 'Headers':
                return 1
            elif name == 'Parameters':
                return 2

        tableNum = detectTable(table)
        new_data = [str(x) for x in data]
        table.insertRow(table.getRowCount(), new_data)
        return table.getRowCount()


    def replaceLine(self, file_path, new_line):
        from tempfile import mkstemp
        from shutil import move
        from os import fdopen, remove
        #Create temp file
        fh, abs_path = mkstemp()
        with fdopen(fh, 'w') as new_file:
            with open(file_path) as old_file:
                for line in old_file:
                    a = re.findall('^Callback_url[ =]+(.+)$', line)
                    if a:
                        for k in a:
                            temp = k.replace("\'", "").replace("\"", "")
                            new_file.write(line.replace(temp, new_line))
                    else:
                        new_file.write(line)
        #Remove original file
        remove(file_path)
        #Move new file
        move(abs_path, file_path)


    def createAnyView(self, _component, gridx, gridy, gridwidth, gridheight, insets):
        self._jPanelConstraints.fill = GridBagConstraints.HORIZONTAL
        self._jPanelConstraints.gridx = gridx
        self._jPanelConstraints.gridy = gridy
        self._jPanelConstraints.gridwidth = gridwidth
        self._jPanelConstraints.gridheight = gridheight
        self._jPanelConstraints.insets = insets
        self._jPanel.add(_component, self._jPanelConstraints)


    def createMenuItems(self, contextMenuInvocation):
        context = contextMenuInvocation.getInvocationContext()
        filterMenu = JMenu("Femida XSS")
        self._contextMenuData = contextMenuInvocation
        if (context == 0 or context == 1 or
            context == 2 or context == 3 or
            context == 8 or context == 9):
            filterMenu.add(JMenuItem("Add to Headers", actionPerformed = self.addToHeadersItem))
            filterMenu.add(JMenuItem("Add to Parameters", actionPerformed = self.addToParametersItem))
            return Arrays.asList(filterMenu)
        return Arrays.asList([])


    def addToHeadersItem(self, event):
        start, end = self._contextMenuData.getSelectionBounds()
        message = self._contextMenuData.getSelectedMessages()[0]
        ctx = self._contextMenuData.getInvocationContext()

        if ctx == 0 or ctx == 2:
            message = message.getRequest()
        elif ctx == 1 or ctx == 3:
            message = message.getResponse()
        else:
            print(ctx)
            return
        try:
            selected_text = self._helpers.bytesToString(message)[start:end]
            self.insertAnyTable(self._tableModelHeaders, [str(selected_text), '1'])
        except Exception:
            pass

    def addToParametersItem(self, event):
        start, end = self._contextMenuData.getSelectionBounds()
        message = self._contextMenuData.getSelectedMessages()[0]
        ctx = self._contextMenuData.getInvocationContext()

        if ctx == 0 or ctx == 2:
            message = message.getRequest()
        elif ctx == 1 or ctx == 3:
            message = message.getResponse()
        else:
            print(ctx)
            return
        try:
            selected_text = self._helpers.bytesToString(message)[start:end]
            self.insertAnyTable(self._tableModelParams, [str(selected_text), '1'])
        except Exception:
            pass


    def starterPack(self):
        self.addFromFileAsync(config.Payloads, self._tableModelPayloads)
        self.addFromFileAsync(config.Headers, self._tableModelHeaders)
        self.addFromFileAsync(config.Parameters, self._tableModelParams)
        self._jTextFieldExt.setText(config.Extensions)
        self.BAD_EXTENSIONS =  config.Extensions.replace(" ", "").split(",")
        self._jTextFieldURL.setText(config.Callback_url)
        self._tableModelPayloads.addTableModelListener(MyTableModelListener(self._tableModelPayloads, self, self._dictPayloads, config.Payloads))
        self._tableModelHeaders.addTableModelListener(MyTableModelListener(self._tableModelHeaders, self, self._dictHeaders, config.Headers))
        self._tableModelParams.addTableModelListener(MyTableModelListener(self._tableModelParams, self, self._dictParams, config.Parameters))

    def setCallbackUrl(self, event):
        self.replaceLine(self.conf_path, self._jTextFieldURL.getText())
        self.appendToResults('New url={} saved.'.format(self._jTextFieldURL.getText()))

    ### Extenstion update callback ###
    def setCallbackExt(self, event):
        extensions = self._jTextFieldExt.getText()
        bad = extensions.replace(" ", "")
        self.BAD_EXTENSIONS = bad.split(",")
    ##################################

    def addToPayload(self, button):
        self.insertAnyTable(self._tableModelPayloads, ['', '1'])

    def addToHeader(self, button):
        self.insertAnyTable(self._tableModelHeaders, ['', '1'])

    def addToParams(self, button):
        self.insertAnyTable(self._tableModelParams, ['', '1'])


    def uploadToPayload(self, button):
        self._returnFileChooser = self.jfc.showDialog(None, "Open")
        if (self._returnFileChooser == JFileChooser.APPROVE_OPTION):
            selectedFile = self.jfc.getSelectedFile()
            self.fileUpload(selectedFile, self._tableModelPayloads)

    def deleteToPayload(self, button):
        try:
            val = self._tableModelPayloads.getValueAt(self._tableModelPayloads.getRowCount()-1, 0)
            self._tableModelPayloads.removeRow(self._tableModelPayloads.getRowCount()-1)
            self._dictPayloads.pop(val)
            self.saveToFileAsync(config.Payloads, self._dictPayloads)
        except Exception as msg:
            # print(msg)
            pass

    def deleteToHeader(self, button):
        try:
            val = self._tableModelHeaders.getValueAt(self._tableModelHeaders.getRowCount()-1, 0)
            self._tableModelHeaders.removeRow(self._tableModelHeaders.getRowCount()-1)
            self._dictHeaders.pop(val)
            self.saveToFileAsync(config.Headers, self._dictHeaders)
        except Exception as msg:
            # print(msg)
            pass

    def deleteToParams(self, button):
        try:
            val = self._tableModelParams.getValueAt(self._tableModelParams.getRowCount()-1, 0)
            self._tableModelParams.removeRow(self._tableModelParams.getRowCount()-1)
            self._dictParams.pop(val)
            self.saveToFileAsync(config.Parameters, self._dictParams)
        except Exception as msg:
            # print(msg)
            pass

    def clearOutput(self, button):
        self._resultsTextArea.setText("")

    def fileUpload(self, path, table):
        with open(str(path), "r") as f:
            for line in f:
                self.insertAnyTable(table, [str(line), '1'])

    def active_scope(self, button):
        if not self.scope_flag:
            self.scope_flag = True
            self._JCheckBox_scope.setBackground(Color.GRAY)
            self.appendToResults("[Attention] Scope mode is activated...\n")
        else:
            self.scope_flag = False
            self._JCheckBox_scope.setBackground(Color.WHITE)
            self.appendToResults("[Attention] Scope mode is deactivated...\n")

    def active_flag(self, button):
        if not self.status_flag:
            self.status_flag = True
            self.submitSearchButton.setBackground(Color.GRAY)
            self.appendToResults("Proxy start...\n")
        else:
            self.status_flag = False
            self.submitSearchButton.setBackground(Color.WHITE)
            self.appendToResults("Proxy stop...\n")


    def overwriteHeader(self, button):
        if not self._overwriteHeader:
            self._overwriteHeader = True
            self._overwriteHeaderButton.setBackground(Color.GRAY)
        else:
            self._overwriteHeader = False
            self._overwriteHeaderButton.setBackground(Color.WHITE)

    def overwriteParam(self, button):
        if not self._overwriteParam:
            self._overwriteParam = True
            self._overwriteParamButton.setBackground(Color.GRAY)
        else:
            self._overwriteParam = False
            self._overwriteParamButton.setBackground(Color.WHITE)


    def forkRequest(self, button):
        if not self._forkRequestParam:
            self._forkRequestParam = True
            self._forkRequestButton.setBackground(Color.GRAY)
        else:
            self._forkRequestParam = False
            self._forkRequestButton.setBackground(Color.WHITE)


    def prepareRequest(self, requestString, messageInfo=None):
        requestString = str(requestString)
        listHeader = re.findall('([\w-]+):\s?(.*)', requestString)
        dictRealHeaders = {x[0].lower():x[1] for x in listHeader}

        selectedPayloads = {}
        for ind, k in enumerate(self._dictPayloads):
            if self._dictPayloads[k] == '1':
                selectedPayloads[k] = '1'
            else:
                continue

        for index, key in enumerate(self._dictHeaders):
            if key.lower() in dictRealHeaders.keys() and self._dictHeaders[key] == '1':
                if len(self._dictPayloads.keys()) == 0:
                    pass
                elif self._overwriteHeader:
                    payload = random.choice(selectedPayloads.keys())
                    payload = payload.replace(r"{URL}", self._jTextFieldURL.getText(), 1)
                    requestString = requestString.replace(dictRealHeaders.get(key.lower()), payload, 1)
                elif not self._overwriteHeader:
                    payload = random.choice(selectedPayloads.keys())
                    payload = payload.replace(r"{URL}", self._jTextFieldURL.getText(), 1)
                    payload = dictRealHeaders.get(key.lower()) + payload
                    requestString = requestString.replace(dictRealHeaders.get(key.lower()), payload, 1)
            else:
                pass

        for index, key in enumerate(self._dictParams):
            analyzed = self._helpers.analyzeRequest(requestString.encode())
            param = analyzed.getParameters()
            dictRealParams = {x.getName().lower(): [x.getValue(), x.getValueStart(), x.getValueEnd()] for x in param}
            if key.lower() in dictRealParams.keys() and self._dictParams[key] == '1':
                if len(self._dictPayloads.keys()) == 0:
                    pass
                elif self._overwriteParam:
                    payload = random.choice(selectedPayloads.keys())
                    payload = payload.replace(r"{URL}", self._jTextFieldURL.getText(), 1)
                    start_word = dictRealParams[key.lower()][1]
                    end_word = dictRealParams[key.lower()][2]
                    requestString = requestString[:start_word] + payload + requestString[end_word:]

                elif not self._overwriteParam:
                    payload = random.choice(selectedPayloads.keys())
                    payload = payload.replace(r"{URL}", self._jTextFieldURL.getText(), 1)
                    payload = dictRealParams[key.lower()][0] + payload
                    start_word = dictRealParams[key.lower()][1]
                    end_word = dictRealParams[key.lower()][2]
                    requestString = requestString[:start_word] + payload + requestString[end_word:]
            else:
                pass
        return requestString

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.status_flag:
            return
        # only process requests
        if not messageIsRequest:
            return
        # Check if url is in scope
        if self.scope_flag:
            URL = messageInfo.getUrl()
            if not self._callbacks.isInScope(URL):
                return
            # Check extensions
            for extension in self.BAD_EXTENSIONS:
                print(extension)
                if str(URL).endswith(extension):
                    return

            if self._forkRequestParam:
                requestString = messageInfo.getRequest().tostring()
                # SOOOO HARD FIX! It should be better
                if requestString[0] == '@':
                    messageInfo.setRequest(self._helpers.stringToBytes(requestString[1:]))
                else:
                    newRequestString = self.prepareRequest(requestString, messageInfo)
                    self.appendToResults('Parallel Request:')
                    self.appendToResults(newRequestString.encode())
                    newRequestString = '@' + newRequestString
                    func = self._callbacks.makeHttpRequest
                    thread = Thread(target=func, args=(messageInfo.getHttpService(), self._helpers.stringToBytes(newRequestString)))
                    thread.start()
            else:
                requestString = messageInfo.getRequest().tostring()
                newRequestString = self.prepareRequest(requestString, messageInfo)
                self.appendToResults(newRequestString.encode())
                messageInfo.setRequest(self._helpers.stringToBytes(newRequestString))

        
    # Fnction to provide output to GUI
    def appendToResults(self, s):
        def appendToResults_run(s):
            self._resultsTextArea.append(s)
            self._resultsTextArea.append('\n')
        swing.SwingUtilities.invokeLater(PyRunnable(appendToResults_run, str(s)))


    def addFromFileAsync(self, file, table):
        def addFromFile_run(file, table):
           if os.path.exists(file):
                with open(file, 'r') as f:
                    for row in f.readlines():
                        if row != '':
                            temp = row[:-1] if row[-1] == '\n' else row
                            self.insertAnyTable(table, [str(temp), '1'])
        swing.SwingUtilities.invokeLater(PyRunnable(addFromFile_run, file, table))


    def saveToFileAsync(self, file, data, isAppend=False):
        def saveToFile_run(file, data, isAppend):
            isAppend = 'w'
            with open(file, isAppend) as f:
                for i, k in enumerate(data):
                    f.write("{}\n".format(k))
                f.seek(-1, os.SEEK_END)
                f.truncate()
        swing.SwingUtilities.invokeLater(PyRunnable(saveToFile_run, file, data, isAppend))


    def getTabCaption(self):
        return self.name

    def getUiComponent(self):
        return self._jPanel
