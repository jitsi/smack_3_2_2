/**
 * $RCSfile$
 * $Revision$
 * $Date$
 *
 * Copyright 2003-2007 Jive Software.
 *
 * All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.smack;

import org.jivesoftware.smack.Connection.ListenerWrapper;
import org.jivesoftware.smack.packet.*;
import org.jivesoftware.smack.sasl.SASLMechanism.Challenge;
import org.jivesoftware.smack.sasl.SASLMechanism.Failure;
import org.jivesoftware.smack.sasl.SASLMechanism.Success;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.xmlpull.mxp1.MXParser;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Listens for XML traffic from the XMPP server and parses it into packet objects.
 * The packet reader also invokes all packet listeners and collectors.<p>
 *
 * @see Connection#createPacketCollector
 * @see Connection#addPacketListener
 * @author Matt Tucker
 * @author Pawel Domas
 */
class PacketReader {

    private static final Logger LOGGER = Logger.getLogger(PacketReader.class.getName());

    private Thread readerThread;
    private ExecutorService listenerExecutor;

    private AbstractConnection connection;
    protected XmlPullParser parser;
    protected boolean done;

    private String streamRoot;

    private Semaphore connectionSemaphore;

    /**
     * Creates new <tt>PacketReader</tt>.
     *
     * @param connection the connection for which the newly created
     * <tt>PacketReader</tt> will be reading packets.
     * @param streamRoot the name of root stream's XML element, when "end tag"
     * for the XML element of this name is parsed, the connection will be
     * disconnected.
     */
    public PacketReader(final AbstractConnection connection,
                        String streamRoot) {
        this.connection = connection;
        this.streamRoot = streamRoot;
        this.init();
    }

    /**
     * Initializes the reader in order to be used. The reader is initialized during the
     * first connection and when reconnecting due to an abruptly disconnection.
     */
    protected void init() {
        done = false;

        readerThread = new Thread() {
            public void run() {
                parsePackets(this);
            }
        };
        readerThread.setName("Smack Packet Reader (" + connection.connectionCounterValue + ")");
        readerThread.setDaemon(true);

        // Create an executor to deliver incoming packets to listeners. We'll use a single
        // thread with an unbounded queue.
        listenerExecutor = Executors.newSingleThreadExecutor(new ThreadFactory() {

            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable,
                        "Smack Listener Processor (" + connection.connectionCounterValue + ")");
                thread.setDaemon(true);
                return thread;
            }
        });

        resetParser();
    }

    /**
     * Starts the packet reader thread and returns once a connection to the server
     * has been established. A connection will be attempted for a maximum of five
     * seconds. An XMPPException will be thrown if the connection fails.
     *
     * @throws XMPPException if the server fails to send an opening stream back
     *      for more than five seconds.
     */
    public void startup() throws XMPPException {
        connectionSemaphore = new Semaphore(1);

        readerThread.start();
        // Wait for stream tag before returing. We'll wait a couple of seconds before
        // giving up and throwing an error.
        try {
            if (!connection.connected) {
                connectionSemaphore.acquire();
            }

            // A waiting thread may be woken up before the wait time or a notify
            // (although this is a rare thing). Therefore, we continue waiting
            // until either a connectionID has been set (and hence a notify was
            // made) or the total wait time has elapsed.
            int waitTime = SmackConfiguration.getPacketReplyTimeout();
            if (!connection.connected) {
                connectionSemaphore.tryAcquire(
                    3 * waitTime, TimeUnit.MILLISECONDS);
            }
        }
        catch (InterruptedException ie) {
            // Ignore.
        }
        if (!connection.connected) {
            throw new XMPPException("Connection failed. No response from server.");
        }
    }

    /**
     * Shuts the packet reader down.
     */
    public void shutdown() {
        // Notify connection listeners of the connection closing if done hasn't already been set.
        if (!done) {
            for (ConnectionListener listener : connection.getConnectionListeners()) {
                try {
                    listener.connectionClosed();
                }
                catch (Exception e) {
                    // Cath and print any exception so we can recover
                    // from a faulty listener and finish the shutdown process
                    LOGGER.log(Level.SEVERE, "faulty listener", e);
                }
            }
        }
        done = true;

        // Shut down the listener executor.
        listenerExecutor.shutdown();
    }

    /**
     * Cleans up all resources used by the packet reader.
     */
    void cleanup() {
        connection.recvListeners.clear();
        connection.collectors.clear();
    }

    /**
     * Sends out a notification that there was an error with the connection
     * and closes the connection.
     *
     * @param e the exception that causes the connection close event.
     */
    void notifyConnectionError(Exception e) {
        done = true;
        // Closes the connection temporary. A reconnection is possible
        connection.shutdown(new Presence(Presence.Type.unavailable));
        // Print the stack trace to help catch the problem
        LOGGER.log(Level.SEVERE, "Closes the connection temporary", e);
        // Notify connection listeners of the error.
        for (ConnectionListener listener : connection.getConnectionListeners()) {
            try {
                listener.connectionClosedOnError(e);
            }
            catch (Exception e2) {
                // Catch and print any exception so we can recover
                // from a faulty listener
                LOGGER.log(Level.SEVERE, "faulty listener", e2);
            }
        }
    }

    /**
     * Sends a notification indicating that the connection was reconnected successfully.
     */
    protected void notifyReconnection() {
        // Notify connection listeners of the reconnection.
        for (ConnectionListener listener : connection.getConnectionListeners()) {
            try {
                listener.reconnectionSuccessful();
            }
            catch (Exception e) {
                // Catch and print any exception so we can recover
                // from a faulty listener
                LOGGER.log(Level.SEVERE, "faulty listener", e);
            }
        }
    }

    /**
     * Resets the parser using the latest connection's reader. Reseting the parser is necessary
     * when the plain connection has been secured or when a new opening stream element is going
     * to be sent by the server.
     */
    protected void resetParser() {
        try {
            parser = new MXParser();
            parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
            parser.setInput(connection.reader);
        }
        catch (XmlPullParserException xppe) {
            LOGGER.log(Level.SEVERE, "parser error", xppe);
        }
    }

    /**
     * Parse top-level packets in order to process them further.
     *
     * @param thread the thread that is being used by the reader to parse incoming packets.
     */
    private void parsePackets(Thread thread) {
         try {
            int eventType = parser.getEventType();
            do {
                if (eventType == XmlPullParser.END_TAG
                        && streamRoot.equals(parser.getName())) {
                    // End of stream - disconnect the connection
                    connection.disconnect();
                } else {
                    doParsePackets(parser);
                }
                eventType = parser.next();
            } while (!done && eventType != XmlPullParser.END_DOCUMENT && thread == readerThread);
        }
        catch (Exception e) {
            if (!done) {
                // Close the connection and notify connection listeners of the
                // error.
                notifyConnectionError(e);
            }
        }
    }

    /**
     * The method is called in the main parsing loop to process top level
     * packets. {@link XmlPullParser#next()} is called automatically and should
     * not be called unless it's ok to consume the element.
     *
     * @param parser the <tt>XmlPullParser</tt>
     */
    protected void doParsePackets(XmlPullParser parser) throws Exception {
        int eventType = parser.getEventType();
        if (eventType == XmlPullParser.START_TAG) {
            if (parser.getName().equals("message")) {
                processPacket(PacketParserUtils.parseMessage(parser));
            }
            else if (parser.getName().equals("iq")) {
                processPacket(PacketParserUtils.parseIQ(parser, connection));
            }
            else if (parser.getName().equals("presence")) {
                processPacket(PacketParserUtils.parsePresence(parser));
            }
            else if (parser.getName().equals("error")) {
                throw new XMPPException(PacketParserUtils.parseStreamError(parser));
            }
            else if (parser.getName().equals("features")) {
                parseFeatures(parser);
            }
            else if (parser.getName().equals("failure")) {
                // SASL authentication has failed. The server may close the connection
                // depending on the number of retries
                final Failure failure = PacketParserUtils.parseSASLFailure(parser);
                processPacket(failure);
                connection.getSASLAuthentication().authenticationFailed(failure.getCondition());
            }
            else if (parser.getName().equals("challenge")) {
                // The server is challenging the SASL authentication made by the client
                String challengeData = parser.nextText();
                processPacket(new Challenge(challengeData));
                connection.getSASLAuthentication().challengeReceived(challengeData);
            }
            else if (parser.getName().equals("success")) {
                processPacket(new Success(parser.nextText()));
                // Let the connection react first
                connection.onSuccessReceived();
                // The SASL authentication with the server was successful. The next step
                // will be to bind the resource
                connection.getSASLAuthentication().authenticated();
            }
        }
    }

    /**
     * Releases the connection lock so that the thread that was waiting can resume. The
     * lock will be released when one of the following three conditions is met (for TCP connection):<p>
     *
     * 1) An opening stream was sent from a non XMPP 1.0 compliant server
     * 2) Stream features were received from an XMPP 1.0 compliant server that does not support TLS
     * 3) TLS negotiation was successful
     *
     * In case of BOSH the method is called when the BOSH client connect's to
     * the server.
     */
    void releaseConnectionIDLock() {
        connectionSemaphore.release();
    }

    /**
     * Processes a packet after it's been fully parsed by looping through the installed
     * packet collectors and listeners and letting them examine the packet to see if
     * they are a match with the filter.
     *
     * @param packet the packet to process.
     */
    private void processPacket(Packet packet) {
        if (packet == null) {
            return;
        }

        // Loop through all collectors and notify the appropriate ones.
        for (PacketCollector collector: connection.getPacketCollectors()) {
            try {
                collector.processPacket(packet);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Faulty PacketCollector", e);
            }
        }

        // Deliver the incoming packet to listeners.
        listenerExecutor.submit(new ListenerNotification(packet));
    }

    private void parseFeatures(XmlPullParser parser) throws Exception {
        boolean done = false;

        while (!done) {
            int eventType = parser.next();

            if (eventType == XmlPullParser.END_TAG
                    && "features".equals(parser.getName())) {
                done = true;
            }

            doParseFeatures(parser);
        }
    }

    protected void doParseFeatures(XmlPullParser parser) throws Exception {
        int eventType = parser.getEventType();

        if (eventType == XmlPullParser.START_TAG) {
            if (parser.getName().equals("mechanisms")) {
                // The server is reporting available SASL mechanisms. Store this information
                // which will be used later while logging (i.e. authenticating) into
                // the server
                connection.getSASLAuthentication()
                    .setAvailableSASLMethods(PacketParserUtils.parseMechanisms(parser));
            }
            else if (parser.getName().equals("bind")) {
                // The server requires the client to bind a resource to the stream
                connection.getSASLAuthentication().bindingRequired();
            }
            else if (parser.getName().equals("session")) {
                // The server supports sessions
                connection.getSASLAuthentication().sessionsSupported();
            }
            else if (parser.getName().equals("register")) {
                connection.getAccountManager().setSupportsAccountCreation(true);
            }
        }
    }

    /**
     * A runnable to notify all listeners of a packet.
     */
    private class ListenerNotification implements Runnable {

        private Packet packet;

        public ListenerNotification(Packet packet) {
            this.packet = packet;
        }

        public void run() {
            for (ListenerWrapper listenerWrapper : connection.recvListeners.values()) {
                listenerWrapper.notifyListener(packet);
            }
        }
    }
}