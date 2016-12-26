/**
 * $RCSfile$
 * $Revision$
 * $Date$
 *
 * Copyright 2009 Jive Software.
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

import org.jivesoftware.smack.filter.PacketFilter;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.util.StringUtils;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Common code shared by both {@link XMPPConnection} and
 * {@link XMPPBOSHConnection}.
 */
abstract class AbstractConnection extends Connection {

    private static final Logger LOGGER = Logger.getLogger(AbstractConnection.class.getName());

    protected String connectionID = null;
    private String user = null;
    protected boolean connected = false;
    /**
     * Flag that indicates if the user is currently authenticated with the server.
     */
    private boolean authenticated = false;
    /**
     * Flag that indicates if the user was authenticated with the server when the connection
     * to the server was closed (abruptly or not).
     */
    private boolean wasAuthenticated = false;
    private boolean anonymous = false;

    protected PacketWriter packetWriter;
    protected PacketReader packetReader;

    private Roster roster = null;

    /**
     * Create a new Connection to a XMPP server.
     *
     * @param configuration The configuration which is used to establish the connection.
     */
    protected AbstractConnection(ConnectionConfiguration configuration) {
        super(configuration);
    }

    /**
     * Establishes a connection to the XMPP server and performs an automatic login
     * only if the previous connection state was logged (authenticated). It basically
     * creates and maintains a socket connection to the server.<p>
     * <p/>
     * Listeners will be preserved from a previous connection if the reconnection
     * occurs after an abrupt termination.
     *
     * @throws XMPPException if an error occurs while trying to establish the connection.
     *      Two possible errors can occur which will be wrapped by an XMPPException --
     *      UnknownHostException (XMPP error code 504), and IOException (XMPP error code
     *      502). The error codes and wrapped exceptions can be used to present more
     *      appropiate error messages to end-users.
     */
    public void connect() throws XMPPException {
        // Establishes the connection, readers and writers
        connectUsingConfiguration(config);

        initConnection();

        // Automatically makes the login if the user was previously connected successfully
        // to the server and the connection was terminated abruptly
        if (connected && wasAuthenticated) {
            // Make the login
            try {
                if (isAnonymous()) {
                    // Make the anonymous login
                    loginAnonymously();
                }
                else {
                    login(config.getUsername(), config.getPassword(),
                            config.getResource());
                }
                packetReader.notifyReconnection();
            }
            catch (XMPPException e) {
                LOGGER.log(Level.SEVERE, "Error login", e);
            }
        }
    }

    /**
     * Implementing class should open transport (connect socket etc.) using
     * information supplied by the configuration.
     *
     * @param config the connection's configuration which contains all the
     * details required to establish new connection to the remote server.
     *
     * @throws XMPPException if fails to connect to remote server.
     */
    protected abstract void connectUsingConfiguration(ConnectionConfiguration config) throws XMPPException;

    /**
     * Initializes the connection by creating a packet reader and writer and opening a
     * XMPP stream to the server.
     *
     * @throws XMPPException if establishing a connection to the server fails.
     */
    protected void initConnection() throws XMPPException {
        boolean isFirstInitialization = packetReader == null || packetWriter == null;

        // Set the reader and writer instance variables
        initReaderAndWriter();

        try {
            if (isFirstInitialization) {
                packetWriter = createPacketWriter();
                packetReader = createPacketReader();

                // If debugging is enabled, we should start the thread that will listen for
                // all packets and then log them.
                if (config.isDebuggerEnabled()) {
                    addPacketListener(debugger.getReaderListener(), null);
                    if (debugger.getWriterListener() != null) {
                        addPacketSendingListener(debugger.getWriterListener(), null);
                    }
                }
            }
            else {
                packetWriter.init();
                packetReader.init();
            }

            // Start the packet writer. This will open a XMPP stream to the server
            packetWriter.startup();
            // Start the packet reader. The startup() method will block until we
            // get an opening stream packet back from server.
            packetReader.startup();

            // Start keep alive process (after TLS was negotiated - if available)
            packetWriter.startKeepAliveProcess();

            if (isFirstInitialization) {
                // Notify listeners that a new connection has been established
                for (ConnectionCreationListener listener : getConnectionCreationListeners()) {
                    listener.connectionCreated(this);
                }
            }
            else if (!wasAuthenticated) {
                packetReader.notifyReconnection();
            }

        }
        catch (XMPPException ex) {
            // An exception occurred in setting up the connection. Make sure we shut down the
            // readers and writers and close the socket.

            if (packetWriter != null) {
                try {
                    packetWriter.shutdown();
                }
                catch (Throwable ignore) { /* ignore */ }
                packetWriter = null;
            }
            if (packetReader != null) {
                try {
                    packetReader.shutdown();
                }
                catch (Throwable ignore) { /* ignore */ }
                packetReader = null;
            }
            if (reader != null) {
                try {
                    reader.close();
                }
                catch (Throwable ignore) { /* ignore */ }
                reader = null;
            }
            if (writer != null) {
                try {
                    writer.close();
                }
                catch (Throwable ignore) {  /* ignore */}
                writer = null;
            }
            initConnectionFailed(ex);
            this.setWasAuthenticated(authenticated);
            authenticated = false;
            connected = false;

            throw ex;        // Everything stopped. Now throw the exception.
        }
    }

    /**
     * Method called during {@link #initConnection()}. Implementing class shall
     * initialize {@link #reader} and {@link #writer}.
     *
     * @throws XMPPException
     */
    protected void initReaderAndWriter() throws XMPPException {
        // If debugging is enabled, we open a window and write out all network traffic.
        initDebugger();
    }

    /**
     * Method called in try catch block of {@link #initConnection()} in case
     * {@link XMPPException} is thrown. Implementing classes should cleanup any
     * resources allocated during {@link #connectUsingConfiguration(ConnectionConfiguration)}.
     *
     * @param ex the <tt>XMPPException</tt> that was thrown.
     */
    protected abstract void initConnectionFailed(XMPPException ex);

    /**
     * Method called during {@link #initConnection()} to initialize
     * {@link #packetReader} field. Will be called only during the first
     * initialization.
     *
     * @return new <tt>{@link PacketReader}</tt> instance.
     */
    protected abstract PacketReader createPacketReader();

    /**
     * Method called during {@link #initConnection()} to initialize
     * {@link #packetWriter} field. Will be called only during the first
     * initialization.
     *
     * @return new <tt>{@link PacketWriter}</tt> instance.
     */
    protected abstract PacketWriter createPacketWriter();

    /**
     * Method called by the {@link PacketReader} when it parses &lt;success&gt;
     * response to the authentication request.
     *
     * @throws IOException if some IO error occurs.
     */
    protected abstract void onSuccessReceived() throws IOException;

    @Override
    public synchronized void login(String username, String password, String resource) throws XMPPException {
        if (!isConnected()) {
            throw new IllegalStateException("Not connected to server.");
        }
        if (authenticated) {
            throw new IllegalStateException("Already logged in to server.");
        }
        // Do partial version of nameprep on the username.
        username = username.toLowerCase().trim();

        String response;
        if (config.isSASLAuthenticationEnabled() &&
            saslAuthentication.hasNonAnonymousAuthentication()) {
            // Authenticate using SASL
            if (password != null) {
                response = saslAuthentication.authenticate(username, password, resource);
            }
            else {
                response = saslAuthentication
                    .authenticate(username, resource, config.getCallbackHandler());
            }
        }
        else {
            // Authenticate using Non-SASL
            response = new NonSASLAuthentication(this).authenticate(username, password, resource);
        }

        // Set the user.
        if (response != null) {
            this.user = response;
            // Update the serviceName with the one returned by the server
            config.setServiceName(StringUtils.parseServer(response));
        }
        else {
            this.user = username + "@" + getServiceName();
            if (resource != null) {
                this.user += "/" + resource;
            }
        }

        // If compression is enabled then request the server to use stream compression
        if (config.isCompressionEnabled()) {
            useCompression();
        }

        // Indicate that we're now authenticated.
        authenticated = true;
        anonymous = false;

        // Create the roster if it is not a reconnection or roster already created by getRoster()
        if (this.roster == null) {
            this.roster = new Roster(this);
        }
        if (config.isRosterLoadedAtLogin()) {
            this.roster.reload();
        }

        // Set presence to online.
        if (config.isSendPresence()) {
            packetWriter.sendPacket(new Presence(Presence.Type.available));
        }

        // Stores the authentication for future reconnection
        config.setLoginInfo(username, password, resource);

        // If debugging is enabled, change the the debug window title to include the
        // name we are now logged-in as.
        // If DEBUG_ENABLED was set to true AFTER the connection was created the debugger
        // will be null
        if (config.isDebuggerEnabled() && debugger != null) {
            debugger.userHasLogged(user);
        }
    }

    @Override
    public synchronized void loginAnonymously() throws XMPPException {
        if (!isConnected()) {
            throw new IllegalStateException("Not connected to server.");
        }
        if (authenticated) {
            throw new IllegalStateException("Already logged in to server.");
        }

        String response;
        if (config.isSASLAuthenticationEnabled() &&
            saslAuthentication.hasAnonymousAuthentication()) {
            response = saslAuthentication.authenticateAnonymously();
        }
        else {
            // Authenticate using Non-SASL
            response = new NonSASLAuthentication(this).authenticateAnonymously();
        }

        // Set the user value.
        this.user = response;
        // Update the serviceName with the one returned by the server
        config.setServiceName(StringUtils.parseServer(response));

        // If compression is enabled then request the server to use stream compression
        if (config.isCompressionEnabled()) {
            useCompression();
        }

        // Set presence to online.
        packetWriter.sendPacket(new Presence(Presence.Type.available));

        // Indicate that we're now authenticated.
        authenticated = true;
        anonymous = true;

        // If debugging is enabled, change the the debug window title to include the
        // name we are now logged-in as.
        // If DEBUG_ENABLED was set to true AFTER the connection was created the debugger
        // will be null
        if (config.isDebuggerEnabled() && debugger != null) {
            debugger.userHasLogged(user);
        }
    }

    public Roster getRoster() {
        // synchronize against login()
        synchronized(this) {
            // if connection is authenticated the roster is already set by login()
            // or a previous call to getRoster()
            if (!isAuthenticated() || isAnonymous()) {
                if (roster == null) {
                    roster = new Roster(this);
                }
                return roster;
            }
        }

        if (!config.isRosterLoadedAtLogin()) {
            roster.reload();
        }
        // If this is the first time the user has asked for the roster after calling
        // login, we want to wait for the server to send back the user's roster. This
        // behavior shields API users from having to worry about the fact that roster
        // operations are asynchronous, although they'll still have to listen for
        // changes to the roster. Note: because of this waiting logic, internal
        // Smack code should be wary about calling the getRoster method, and may need to
        // access the roster object directly.
        if (!roster.rosterInitialized) {
            try {
                synchronized (roster) {
                    long waitTime = SmackConfiguration.getPacketReplyTimeout();
                    long start = System.currentTimeMillis();
                    while (!roster.rosterInitialized) {
                        if (waitTime <= 0) {
                            break;
                        }
                        roster.wait(waitTime);
                        long now = System.currentTimeMillis();
                        waitTime -= now - start;
                        start = now;
                    }
                }
            }
            catch (InterruptedException ie) {
                // Ignore.
            }
        }
        return roster;
    }

    /**
     * Instructs the implementing class to enable stream compression. Method
     * called from either {@link #login(String, String, String)} or
     * {@link #loginAnonymously()}, before 'available' presence is sent if
     * compression is enabled in the configuration.
     *
     * @return true if stream compression negotiation was successful.
     */
    protected abstract boolean useCompression();

    public synchronized void disconnect(Presence unavailablePresence) {
        // If not connected, ignore this request.
        if (packetReader == null || packetWriter == null) {
            return;
        }

        shutdown(unavailablePresence);

        if (roster != null) {
            roster.cleanup();
            roster = null;
        }

        wasAuthenticated = false;

        packetWriter.cleanup();
        packetWriter = null;
        packetReader.cleanup();
        packetReader = null;
    }

    public void sendPacket(Packet packet) {
        if (!isConnected()) {
            throw new IllegalStateException("Not connected to server.");
        }
        if (packet == null) {
            throw new NullPointerException("Packet is null.");
        }
        packetWriter.sendPacket(packet);
    }

    /**
     * Registers a packet interceptor with this connection. The interceptor will be
     * invoked every time a packet is about to be sent by this connection. Interceptors
     * may modify the packet to be sent. A packet filter determines which packets
     * will be delivered to the interceptor.
     *
     * @param packetInterceptor the packet interceptor to notify of packets about to be sent.
     * @param packetFilter      the packet filter to use.
     * @deprecated replaced by {@link Connection#addPacketInterceptor(PacketInterceptor, PacketFilter)}.
     */
    public void addPacketWriterInterceptor(PacketInterceptor packetInterceptor,
                                           PacketFilter packetFilter) {
        addPacketInterceptor(packetInterceptor, packetFilter);
    }

    /**
     * Removes a packet interceptor.
     *
     * @param packetInterceptor the packet interceptor to remove.
     * @deprecated replaced by {@link Connection#removePacketInterceptor(PacketInterceptor)}.
     */
    public void removePacketWriterInterceptor(PacketInterceptor packetInterceptor) {
        removePacketInterceptor(packetInterceptor);
    }

    /**
     * Registers a packet listener with this connection. The listener will be
     * notified of every packet that this connection sends. A packet filter determines
     * which packets will be delivered to the listener. Note that the thread
     * that writes packets will be used to invoke the listeners. Therefore, each
     * packet listener should complete all operations quickly or use a different
     * thread for processing.
     *
     * @param packetListener the packet listener to notify of sent packets.
     * @param packetFilter   the packet filter to use.
     * @deprecated replaced by {@link #addPacketSendingListener(PacketListener, PacketFilter)}.
     */
    public void addPacketWriterListener(PacketListener packetListener, PacketFilter packetFilter) {
        addPacketSendingListener(packetListener, packetFilter);
    }

    /**
     * Removes a packet listener for sending packets from this connection.
     *
     * @param packetListener the packet listener to remove.
     * @deprecated replaced by {@link #removePacketSendingListener(PacketListener)}.
     */
    public void removePacketWriterListener(PacketListener packetListener) {
        removePacketSendingListener(packetListener);
    }

    /**
     * Closes the connection by setting presence to unavailable then closing the stream to
     * the XMPP server. The shutdown logic will be used during a planned disconnection or when
     * dealing with an unexpected disconnection. Unlike {@link #disconnect()} the connection's
     * packet reader, packet writer, and {@link Roster} will not be removed; thus
     * connection's state is kept.
     *
     * @param unavailablePresence the presence packet to send during shutdown.
     */
    public void shutdown(Presence unavailablePresence) {
        // Set presence to offline
        packetWriter.sendPacket(unavailablePresence);

        this.setWasAuthenticated(authenticated);
        authenticated = false;
        connected = false;

        packetReader.shutdown();
        packetWriter.shutdown();
        // Wait 150 ms for processes to clean-up, then shutdown.
        try {
            Thread.sleep(150);
        }
        catch (Exception e) {
            // Ignore.
        }

        // Close down the readers and writers.
        if (reader != null) {
            try {
                reader.close();
            }
            catch (Throwable ignore) { /* ignore */ }
            reader = null;
        }
        if (writer != null) {
            try {
                writer.close();
            }
            catch (Throwable ignore) { /* ignore */ }
            writer = null;
        }

        saslAuthentication.init();
    }

    /**
     * Sets whether the connection has already logged in the server.
     *
     * @param wasAuthenticated true if the connection has already been authenticated.
     */
    private void setWasAuthenticated(boolean wasAuthenticated) {
        // Never reset the flag if the connection has ever been authenticated
        if (!this.wasAuthenticated) {
            this.wasAuthenticated = wasAuthenticated;
        }
    }

    public String getConnectionID() {
        if (!isConnected()) {
            return null;
        }
        return connectionID;
    }

    public String getUser() {
        if (!isAuthenticated()) {
            return null;
        }
        return user;
    }

    public boolean isConnected() {
        return connected;
    }

    public boolean isAnonymous() {
        return anonymous;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }
}
