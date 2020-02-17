package burp;

import com.bishopfox.gadgetprobe.GadgetProbe;

import java.awt.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

public class InteractionServer extends Thread {

    private IBurpExtenderCallbacks callbacks;
    private IBurpCollaboratorClientContext collaboratorContext;

    private PrintWriter stdout;
    private PrintWriter stderr;

    private final Object pauseLock = new Object();
    private volatile boolean paused = false;
    private volatile boolean goOn;

    private int pollingMilliseconds = 30000;
    private Date lastPollingDate;

    private static GadgetProbe gadgetProbe;
    private BurpGui guiManager;

    public static GadgetProbe getGadgetProbe() {
        return gadgetProbe;
    }

    public InteractionServer(IBurpExtenderCallbacks callbacks, IBurpCollaboratorClientContext initialCollaboratorContext, BurpGui guiManager) {

        this.callbacks = callbacks;
        this.guiManager = guiManager;

        // Initialize stdout and stderr
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);


        if(initialCollaboratorContext != null) {
            this.gadgetProbe = new GadgetProbe(initialCollaboratorContext.generatePayload(true));
            collaboratorContext = initialCollaboratorContext;
        } else {
            stdout.println("Collaborator disabled");
        }

        this.goOn = true;

    }

    public void setPollingMilliseconds(int pollingMilliseconds) {
        this.pollingMilliseconds = pollingMilliseconds;
    }

    public void setGoOn(boolean goOn) {
        this.goOn = goOn;
    }

    public void pause() {
        paused = true;
        stdout.println("Stopping Collaborator interactions polling");
    }

    public void resumeThread() {
        synchronized (pauseLock) {
            paused = false;
            pauseLock.notifyAll(); // Unblocks thread
        }
        stdout.println("Restarting Collaborator interactions polling");
    }

    public void setCollaboratorContext(IBurpCollaboratorClientContext collaboratorContext) {
        this.gadgetProbe = new GadgetProbe(collaboratorContext.getCollaboratorServerLocation());
    }

    public void run() {

        stdout.println("Thread started");

        DateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        lastPollingDate = null;

        while(goOn) {

            synchronized (pauseLock) {

                // Maybe is changed while waiting for pauseLock
                if(!goOn) {
                    break;
                }

                if (paused) {
                    try {
                        pauseLock.wait();
                    } catch (InterruptedException e) {
                        stderr.println("Exception with wait/notify");
                        stderr.println(e.toString());
                    }
                    // Maybe is changed while waiting for pauseLock
                    if(!goOn) {
                        break;
                    }
                }

            }

            Date date = new Date();
            if(lastPollingDate == null || (date.getTime() - lastPollingDate.getTime()) > pollingMilliseconds) {
                stdout.println("**** " + dateFormat.format(date) + " ****");
                try {
                    stdout.println("Polling " + collaboratorContext.getCollaboratorServerLocation());
                    stdout.println("Classes found: " + guiManager.getClassesFoundLength());
                } catch(IllegalStateException e) {
                    stdout.println("Can't fetch interactions while Collaborator is disabled (Burp Suite limitation)");
                } catch(Exception f) {
                    stdout.println("Exception");
                    StringWriter sw = new StringWriter();
                    PrintWriter pw = new PrintWriter(sw);
                    f.printStackTrace(pw);
                    stdout.println(sw.toString());
                }
                stdout.println();
                lastPollingDate = date;
            }

            try {

                List<IBurpCollaboratorInteraction> allCollaboratorInteractions = collaboratorContext.fetchAllCollaboratorInteractions();

                for(int j=0;  j < allCollaboratorInteractions.size(); j++) {

                    // HACKY DNS parsing :)
                    IBurpCollaboratorInteraction interaction = allCollaboratorInteractions.get(j);
                    if(interaction.getProperty("type").equals("DNS") && interaction.getProperty("query_type").startsWith("A")) {
                        byte[] bytes = Base64.getDecoder().decode(interaction.getProperty("raw_query"));
                        StringBuilder sb = new StringBuilder();

                        int i = 12;
                        do {
                            int chunk_len = (int)bytes[i++];
                            if (i + chunk_len < bytes.length) {
                                String chunk = new String(Arrays.copyOfRange(bytes, i, i + chunk_len));
                                if (chunk.equals(interaction.getProperty("interaction_id"))) {
                                    if (sb.length() > 1) {
                                        sb.deleteCharAt(sb.length() - 1);
                                    }
                                    break;
                                }
                                sb.append(chunk);
                                sb.append(".");
                                i += chunk_len;
                            }
                        } while ( i < bytes.length);

                        guiManager.addClassFound(sb.toString());
                    }

                }

            } catch(IllegalStateException e) {
                stdout.println("Can't fetch interactions while Collaborator is disabled (Burp Suite limitation)");
            } catch(Exception f) {
                stdout.println("Exception");
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                f.printStackTrace(pw);
                stdout.println(sw.toString());
            }

            try {
                Thread.sleep(pollingMilliseconds);
            } catch (InterruptedException e) {
                stdout.println("InteractionServer: Thread interrupted.");
            }

        }

    }

    public void pollNow() {
        lastPollingDate = null;
    }

    public void reset() {
        collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        this.gadgetProbe = new GadgetProbe(collaboratorContext.generatePayload(true));
    }
}