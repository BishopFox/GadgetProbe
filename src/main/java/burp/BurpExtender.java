package burp;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;

import com.bishopfox.gadgetprobe.GadgetProbe;
import org.json.*;


import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

public class BurpExtender implements IBurpExtender, ActionListener, IIntruderPayloadProcessor, IExtensionStateListener, ITab {
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    private PrintWriter stdout;
    private PrintWriter stderr;

    private IBurpCollaboratorClientContext collaboratorContext;

    private InteractionServer interactionServer;

    private String currentCollaboratorLocation;
    private boolean currentCollaboratorPollOverUnenecryptedHttp;
    private String currentCollaboratorPollingLocation;
    private String currentCollaboratorType;

    private JPanel mainPanel;
    private BurpGui guiManager;


    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {


        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        this.callbacks = callbacks;


        // set our extension name
        callbacks.setExtensionName("GadgetProbe");

        // register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(this);

        //register to get extension state changes
        callbacks.registerExtensionStateListener(this);

        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        stdout.println("GadgetProbe Initialized!");
        stdout.println("Learn more: https://github.com/BishopFox/GadgetProbe");
        stdout.println("");

        initializeCurrentCollaboratorVariables();

        if(!(currentCollaboratorType.equals("none"))) {
            collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        } else {
            collaboratorContext = null;
        }
        guiManager = new BurpGui();
        guiManager.setupListeners(this::actionPerformed);


        interactionServer = new InteractionServer(callbacks, collaboratorContext, guiManager);

        interactionServer.start();

        SwingUtilities.invokeLater(new Runnable()  {

            @Override
            public void run()  {

                mainPanel = (JPanel) guiManager.$$$getRootComponent$$$();
                callbacks.customizeUiComponent(mainPanel);
                callbacks.addSuiteTab(BurpExtender.this);
            }

        });

    }


    @Override
    public String getProcessorName()
    {
        return "ClassName to GadgetProbe";
    }

    private byte[] convertToBytes(Object object) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeObject(object);
            return bos.toByteArray();
        }
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue)
    {
        GadgetProbe gp = InteractionServer.getGadgetProbe();
        String className = helpers.bytesToString(currentPayload);

        Object obj = null;
        try {
            obj = gp.getObject(className);
        } catch (SecurityException e) {
            String msg = "Error: Class name is in protected package. Most likely a typo: " + className;
            stderr.println(msg);
            guiManager.consolePrintln(msg);
            return currentPayload;
        }
        if (obj != null) {
            try {
                guiManager.addClassNotFound(className);
                return convertToBytes(obj);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            String msg = "Error: Class name contains unsupported characters: " + className;
            stderr.println(msg);
            guiManager.consolePrintln(msg);
        }
        return currentPayload;
    }


    public void initializeCurrentCollaboratorVariables() {

        String collaboratorOption = callbacks.saveConfigAsJson("project_options.misc.collaborator_server");
        JSONObject rootJsonObject = new JSONObject(collaboratorOption);
        currentCollaboratorLocation = rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("location");
        currentCollaboratorPollOverUnenecryptedHttp = rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getBoolean("poll_over_unencrypted_http");
        currentCollaboratorPollingLocation = rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("polling_location");
        currentCollaboratorType = rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("type");

    }

    public boolean isCollaboratorChanged() {

        String collaboratorOption = callbacks.saveConfigAsJson("project_options.misc.collaborator_server");
        JSONObject rootJsonObject = new JSONObject(collaboratorOption);

        if(!(currentCollaboratorLocation.equals(rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("location"))) ||
                !(currentCollaboratorPollOverUnenecryptedHttp == rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getBoolean("poll_over_unencrypted_http")) ||
                !(currentCollaboratorPollingLocation.equals(rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("polling_location"))) ||
                !(currentCollaboratorType.equals(rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("type"))) ) {
            return true;
        } else {
            return false;
        }

    }

    public void checkCollaboratorChanges() {
        if(isCollaboratorChanged()) {

            initializeCurrentCollaboratorVariables();

            if(!(currentCollaboratorType.equals("none"))) {

                stdout.println("Collaborator location changed! Setting a new collaborator context to the polling thread!");
                collaboratorContext = callbacks.createBurpCollaboratorClientContext();
                interactionServer.setCollaboratorContext(collaboratorContext);

            } else {
                collaboratorContext = null;
                stdout.println("Collaborator disabled!");

            }

        }

    }

    public void actionPerformed(ActionEvent event) {
        String command = event.getActionCommand();

        if(command.equals("enableDisablePolling")) {
            if(guiManager.isPollingEnabled()) {
                interactionServer.resumeThread();
            } else {
                interactionServer.pause();
            }
        }
        else if(command.equals("pollNow")) {
            interactionServer.pollNow();
            interactionServer.interrupt();
        }
        else if(command.equals("refreshDNS")) {
            interactionServer.reset();
        }
        else if(command.equals("clearConsole")) {
            guiManager.clearConsole();
        }
        else if(command.equals("detectLibraryVersion")) {
            String output = Analyzer.Analyze(guiManager.getClassesFound(), guiManager.getClassesNotFound());
            guiManager.consolePrintln(output);
        }
        else if(command.equals("copyWordlist")) {
            Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
            cb.setContents(new StringSelection(Analyzer.getWordlist()), null);
        }
        else if(command.equals("reset")) {
            guiManager.reset();
            interactionServer.reset();
        }
        else if(command.startsWith("KEY_TYPED")) {
            try {
                long pollingInterval = MILLISECONDS.convert(Integer.parseInt(command.split(",")[1]), SECONDS);
                if (pollingInterval > 60000) {
                    guiManager.consolePrintln("Refusing to set interval longer than 60 seconds");
                } else {
                    interactionServer.setPollingMilliseconds((int) pollingInterval);
                }

            }  catch(NumberFormatException e){
                guiManager.consolePrintln("ERROR: Invalid Polling Interval");
            }
        }
        else {
            guiManager.consolePrintln("ERROR: COMMAND NOT REGISTERED: " + command);
        }
    }

    public void extensionUnloaded() {

        stdout.println("Stopping thread of Collaborator interaction server");
        interactionServer.setGoOn(false);

    }

    @Override
    public String getTabCaption() {
        return "GadgetProbe";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

}
