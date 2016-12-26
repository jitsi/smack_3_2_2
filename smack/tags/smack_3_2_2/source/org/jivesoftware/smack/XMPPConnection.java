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

import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.jivesoftware.smack.util.TLSUtils;
import org.xmlpull.v1.XmlPullParser;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Creates a socket connection to a XMPP server. This is the default connection
 * to a Jabber server and is specified in the XMPP Core (RFC 3920).
 * 
 * @see Connection
 * @author Matt Tucker
 * @author Pawel Domas
 */
public class XMPPConnection extends AbstractConnection {

    private static final Logger LOGGER = Logger.getLogger(XMPPConnection.class.getName());

    /**
     * The socket which is used for this connection.
     */
    private Socket socket;

    private boolean usingTLS = false;

    /**
     * Collection of available stream compression methods offered by the server.
     */
    private Collection<String> compressionMethods;
    /**
     * Flag that indicates if stream compression is actually in use.
     */
    private boolean usingCompression;


    /**
     * Creates a new connection to the specified XMPP server. A DNS SRV lookup will be
     * performed to determine the IP address and port corresponding to the
     * service name; if that lookup fails, it's assumed that server resides at
     * <tt>serviceName</tt> with the default port of 5222. Encrypted connections (TLS)
     * will be used if available, stream compression is disabled, and standard SASL
     * mechanisms will be used for authentication.<p>
     * <p/>
     * This is the simplest constructor for connecting to an XMPP server. Alternatively,
     * you can get fine-grained control over connection settings using the
     * {@link #XMPPConnection(ConnectionConfiguration)} constructor.<p>
     * <p/>
     * Note that XMPPConnection constructors do not establish a connection to the server
     * and you must call {@link #connect()}.<p>
     * <p/>
     * The CallbackHandler will only be used if the connection requires the client provide
     * an SSL certificate to the server. The CallbackHandler must handle the PasswordCallback
     * to prompt for a password to unlock the keystore containing the SSL certificate.
     *
     * @param serviceName the name of the XMPP server to connect to; e.g. <tt>example.com</tt>.
     * @param callbackHandler the CallbackHandler used to prompt for the password to the keystore.
     */
    public XMPPConnection(String serviceName, CallbackHandler callbackHandler) {
        // Create the configuration for this new connection
        super(new ConnectionConfiguration(serviceName));
        config.setCompressionEnabled(false);
        config.setSASLAuthenticationEnabled(true);
        config.setDebuggerEnabled(DEBUG_ENABLED);
        config.setCallbackHandler(callbackHandler);
    }

    /**
     * Creates a new XMPP connection in the same way {@link #XMPPConnection(String,CallbackHandler)} does, but
     * with no callback handler for password prompting of the keystore.  This will work
     * in most cases, provided the client is not required to provide a certificate to 
     * the server.
     *
     * @param serviceName the name of the XMPP server to connect to; e.g. <tt>example.com</tt>.
     */
    public XMPPConnection(String serviceName) {
        // Create the configuration for this new connection
        super(new ConnectionConfiguration(serviceName));
        config.setCompressionEnabled(false);
        config.setSASLAuthenticationEnabled(true);
        config.setDebuggerEnabled(DEBUG_ENABLED);
    }

    /**
     * Creates a new XMPP connection in the same way {@link #XMPPConnection(ConnectionConfiguration,CallbackHandler)} does, but
     * with no callback handler for password prompting of the keystore.  This will work
     * in most cases, provided the client is not required to provide a certificate to 
     * the server.
     *
     *
     * @param config the connection configuration.
     */
    public XMPPConnection(ConnectionConfiguration config) {
        super(config);
    }

    /**
     * Creates a new XMPP connection using the specified connection configuration.<p>
     * <p/>
     * Manually specifying connection configuration information is suitable for
     * advanced users of the API. In many cases, using the
     * {@link #XMPPConnection(String)} constructor is a better approach.<p>
     * <p/>
     * Note that XMPPConnection constructors do not establish a connection to the server
     * and you must call {@link #connect()}.<p>
     * <p/>
     *
     * The CallbackHandler will only be used if the connection requires the client provide
     * an SSL certificate to the server. The CallbackHandler must handle the PasswordCallback
     * to prompt for a password to unlock the keystore containing the SSL certificate.
     *
     * @param config the connection configuration.
     * @param callbackHandler the CallbackHandler used to prompt for the password to the keystore.
     */
    public XMPPConnection(ConnectionConfiguration config, CallbackHandler callbackHandler) {
        super(config);
        config.setCallbackHandler(callbackHandler);
    }

    public boolean isSecureConnection() {
        return isUsingTLS();
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

        super.shutdown(unavailablePresence);

        try {
            if (socket != null) {
                socket.close();
            }
        }
        catch (Exception e) {
            // Ignore.
        }
    }

    protected void connectUsingConfiguration(ConnectionConfiguration config) throws XMPPException {
        String host = config.getHost();
        int port = config.getPort();
        try {
            if (config.getSocketFactory() == null) {
                this.socket = new Socket(host, port);
            }
            else {
                this.socket = config.getSocketFactory().createSocket(host, port);
            }
        }
        catch (UnknownHostException uhe) {
            String errorMessage = "Could not connect to " + host + ":" + port + ".";
            throw new XMPPException(errorMessage, new XMPPError(
                    XMPPError.Condition.remote_server_timeout, errorMessage),
                    uhe);
        }
        catch (IOException ioe) {
            String errorMessage = "XMPPError connecting to " + host + ":"
                    + port + ".";
            throw new XMPPException(errorMessage, new XMPPError(
                    XMPPError.Condition.remote_server_error, errorMessage), ioe);
        }
    }

    @Override
    protected void initConnectionFailed(XMPPException ex) {
        if (socket != null) {
            try {
                socket.close();
            }
            catch (Exception e) { /* ignore */ }
            socket = null;
        }
    }

    @Override
    protected void onSuccessReceived() throws IOException {
        // We now need to bind a resource for the connection
        // Open a new stream and wait for the response
        packetWriter.openStream();
        // Reset the state of the parser since a new stream element is going
        // to be sent by the server
        packetReader.resetParser();
    }

    /**
     * Initializes the connection by creating a packet reader and writer and opening a
     * XMPP stream to the server.
     *
     * @throws XMPPException if establishing a connection to the server fails.
     */
    protected void initConnection() throws XMPPException {
        boolean isFirstInitialization = packetReader == null || packetWriter == null;
        if (!isFirstInitialization) {
            usingCompression = false;
        }

        super.initConnection();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected PacketWriter createPacketWriter() {
        return new TCPXmppPacketWriter();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected PacketReader createPacketReader() {
        return new TCPXmppPacketReader();
    }

    protected void initReaderAndWriter() throws XMPPException {
        try {
            if (!usingCompression) {
                reader =
                        new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
                writer = new BufferedWriter(
                        new OutputStreamWriter(socket.getOutputStream(), "UTF-8"));
            }
            else {
                try {
                    Class<?> zoClass = Class.forName("com.jcraft.jzlib.ZOutputStream");
                    Constructor<?> constructor =
                            zoClass.getConstructor(OutputStream.class, Integer.TYPE);
                    Object out = constructor.newInstance(socket.getOutputStream(), 9);
                    Method method = zoClass.getMethod("setFlushMode", Integer.TYPE);
                    method.invoke(out, 2);
                    writer =
                            new BufferedWriter(new OutputStreamWriter((OutputStream) out, "UTF-8"));

                    Class<?> ziClass = Class.forName("com.jcraft.jzlib.ZInputStream");
                    constructor = ziClass.getConstructor(InputStream.class);
                    Object in = constructor.newInstance(socket.getInputStream());
                    method = ziClass.getMethod("setFlushMode", Integer.TYPE);
                    method.invoke(in, 2);
                    reader = new BufferedReader(new InputStreamReader((InputStream) in, "UTF-8"));
                }
                catch (Exception e) {
                    LOGGER.log(Level.INFO, "Error writing packet", e);
                    reader = new BufferedReader(
                            new InputStreamReader(socket.getInputStream(), "UTF-8"));
                    writer = new BufferedWriter(
                            new OutputStreamWriter(socket.getOutputStream(), "UTF-8"));
                }
            }
        }
        catch (IOException ioe) {
            throw new XMPPException(
                    "XMPPError establishing connection with server.",
                    new XMPPError(XMPPError.Condition.remote_server_error,
                            "XMPPError establishing connection with server."),
                    ioe);
        }

        super.initReaderAndWriter();
    }

    /***********************************************
     * TLS code below
     **********************************************/

    /**
     * Returns true if the connection to the server has successfully negotiated TLS. Once TLS
     * has been negotiatied the connection has been secured.
     *
     * @return true if the connection to the server has successfully negotiated TLS.
     */
    public boolean isUsingTLS() {
        return usingTLS;
    }

    /**
     * Notification message saying that the server supports TLS so confirm the server that we
     * want to secure the connection.
     *
     * @param required true when the server indicates that TLS is required.
     */
    private void startTLSReceived(boolean required) {
        if (required && config.getSecurityMode() ==
                ConnectionConfiguration.SecurityMode.disabled) {
            packetReader.notifyConnectionError(new IllegalStateException(
                    "TLS required by server but not allowed by connection configuration"));
            return;
        }

        if (config.getSecurityMode() == ConnectionConfiguration.SecurityMode.disabled) {
            // Do not secure the connection using TLS since TLS was disabled
            return;
        }
        try {
            writer.write("<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>");
            writer.flush();
        }
        catch (IOException e) {
            packetReader.notifyConnectionError(e);
        }
    }

    /**
     * The server has indicated that TLS negotiation can start. We now need to secure the
     * existing plain connection and perform a handshake. This method won't return until the
     * connection has finished the handshake or an error occured while securing the connection.
     *
     * @throws Exception if an exception occurs.
     */
    private void proceedTLSReceived() throws Exception {
        KeyStore ks = null;
        KeyManager[] kms = null;
        PasswordCallback pcb = null;

        if(config.getCallbackHandler() == null) {
           ks = null;
        } else {
            //System.out.println("Keystore type: "+configuration.getKeystoreType());
            if(config.getKeystoreType().equals("NONE")) {
                ks = null;
                pcb = null;
            }
            else if(config.getKeystoreType().equals("PKCS11")) {
                try {
                    Constructor c = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class);
                    String pkcs11Config = "name = SmartCard\nlibrary = "+config.getPKCS11Library();
                    ByteArrayInputStream config = new ByteArrayInputStream(pkcs11Config.getBytes());
                    Provider p = (Provider)c.newInstance(config);
                    Security.addProvider(p);
                    ks = KeyStore.getInstance("PKCS11",p);
                    pcb = new PasswordCallback("PKCS11 Password: ",false);
                    this.config.getCallbackHandler().handle(new Callback[]{pcb});
                    ks.load(null,pcb.getPassword());
                }
                catch (Exception e) {
                    ks = null;
                    pcb = null;
                }
            }
            else if(config.getKeystoreType().equals("Apple")) {
                ks = KeyStore.getInstance("KeychainStore","Apple");
                ks.load(null,null);
                //pcb = new PasswordCallback("Apple Keychain",false);
                //pcb.setPassword(null);
            }
            else {
                ks = KeyStore.getInstance(config.getKeystoreType());
                try {
                    pcb = new PasswordCallback("Keystore Password: ",false);
                    config.getCallbackHandler().handle(new Callback[]{pcb});
                    ks.load(new FileInputStream(config.getKeystorePath()), pcb.getPassword());
                }
                catch(Exception e) {
                    ks = null;
                    pcb = null;
                }
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            try {
                if(pcb == null) {
                    kmf.init(ks,null);
                } else {
                    kmf.init(ks,pcb.getPassword());
                    pcb.clearPassword();
                }
                kms = kmf.getKeyManagers();
            } catch (NullPointerException npe) {
                kms = null;
            }
        }

        // Verify certificate presented by the server
        SSLContext context = config.getCustomSSLContext();
        if(context == null) {
            context = SSLContext.getInstance("TLS");
            context.init(kms,
                    new javax.net.ssl.TrustManager[]{
                            new ServerTrustManager(getServiceName(), config)},
                    new java.security.SecureRandom());
        }

        Socket plain = socket;
        // Secure the plain connection
        socket = context.getSocketFactory().createSocket(plain,
                plain.getInetAddress().getHostAddress(), plain.getPort(), true);
        socket.setSoTimeout(0);
        socket.setKeepAlive(true);
        // Initialize the reader and writer with the new secured version
        initReaderAndWriter();

        final SSLSocket sslSocket = (SSLSocket) socket;
        TLSUtils.setEnabledProtocolsAndCiphers(sslSocket,
                config.getEnabledSSLProtocols(), config.getEnabledSSLCiphers());

        // Proceed to do the handshake
        sslSocket.startHandshake();
        //if (((SSLSocket) socket).getWantClientAuth()) {
        //    System.err.println("Connection wants client auth");
        //}
        //else if (((SSLSocket) socket).getNeedClientAuth()) {
        //    System.err.println("Connection needs client auth");
        //}
        //else {
        //    System.err.println("Connection does not require client auth");
       // }
        // Set that TLS was successful
        usingTLS = true;

        // Reset the state of the parser since a new stream element is going
        // to be sent by the server
        packetReader.resetParser();
        // Set the new  writer to use
        packetWriter.setWriter(writer);
        // Send a new opening stream to the server
        packetWriter.openStream();
    }

    /**
     * Sets the available stream compression methods offered by the server.
     *
     * @param methods compression methods offered by the server.
     */
    private void setAvailableCompressionMethods(Collection<String> methods) {
        compressionMethods = methods;
    }

    /**
     * Returns true if the specified compression method was offered by the server.
     *
     * @param method the method to check.
     * @return true if the specified compression method was offered by the server.
     */
    private boolean hasAvailableCompressionMethod(String method) {
        return compressionMethods != null && compressionMethods.contains(method);
    }

    public boolean isUsingCompression() {
        return usingCompression;
    }

    /**
     * Starts using stream compression that will compress network traffic. Traffic can be
     * reduced up to 90%. Therefore, stream compression is ideal when using a slow speed network
     * connection. However, the server and the client will need to use more CPU time in order to
     * un/compress network data so under high load the server performance might be affected.<p>
     * <p/>
     * Stream compression has to have been previously offered by the server. Currently only the
     * zlib method is supported by the client. Stream compression negotiation has to be done
     * before authentication took place.<p>
     * <p/>
     * Note: to use stream compression the smackx.jar file has to be present in the classpath.
     *
     * @return true if stream compression negotiation was successful.
     */
    protected boolean useCompression() {
        // If stream compression was offered by the server and we want to use
        // compression then send compression request to the server
        if (isAuthenticated()) {
            throw new IllegalStateException("Compression should be negotiated before authentication.");
        }
        try {
            Class.forName("com.jcraft.jzlib.ZOutputStream");
        }
        catch (ClassNotFoundException e) {
            throw new IllegalStateException("Cannot use compression. Add smackx.jar to the classpath");
        }
        if (hasAvailableCompressionMethod("zlib")) {
            requestStreamCompression();
            // Wait until compression is being used or a timeout happened
            synchronized (this) {
                try {
                    this.wait(SmackConfiguration.getPacketReplyTimeout() * 5);
                }
                catch (InterruptedException e) {
                    // Ignore.
                }
            }
            return usingCompression;
        }
        return false;
    }

    /**
     * Request the server that we want to start using stream compression. When using TLS
     * then negotiation of stream compression can only happen after TLS was negotiated. If TLS
     * compression is being used the stream compression should not be used.
     */
    private void requestStreamCompression() {
        try {
            writer.write("<compress xmlns='http://jabber.org/protocol/compress'>");
            writer.write("<method>zlib</method></compress>");
            writer.flush();
        }
        catch (IOException e) {
            packetReader.notifyConnectionError(e);
        }
    }

    /**
     * Start using stream compression since the server has acknowledged stream compression.
     *
     * @throws Exception if there is an exception starting stream compression.
     */
    private void startStreamCompression() throws Exception {
        // Secure the plain connection
        usingCompression = true;
        // Initialize the reader and writer with the new secured version
        initReaderAndWriter();

        // Set the new  writer to use
        packetWriter.setWriter(writer);
        // Send a new opening stream to the server
        packetWriter.openStream();
        // Notify that compression is being used
        synchronized (this) {
            this.notify();
        }
    }

    /**
     * Notifies the XMPP connection that stream compression was denied so that
     * the connection process can proceed.
     */
    private void streamCompressionDenied() {
        synchronized (this) {
            this.notify();
        }
    }

    /**
     * The currently used socket.
     * @return the currently used socket.
     */
    @Override
    public Socket getSocket()
    {
        return socket;
    }

    class TCPXmppPacketWriter extends PacketWriter {

        /**
         * Creates a new packet writer.
         */
        TCPXmppPacketWriter() {
            super(XMPPConnection.this, true);
        }

        /**
         * Sends to the server a new stream element. This operation may be requested several times
         * so we need to encapsulate the logic in one place. This message will be sent while doing
         * TLS, SASL and resource binding.
         *
         * @throws IOException If an error occurs while sending the stanza to the server.
         */
        @Override
        protected void openStream() throws IOException {
            StringBuilder stream = new StringBuilder();
            stream.append("<stream:stream");
            stream.append(" to=\"").append(getServiceName()).append("\"");
            stream.append(" xmlns=\"jabber:client\"");
            stream.append(" xmlns:stream=\"http://etherx.jabber.org/streams\"");
            stream.append(" version=\"1.0\">");
            writer.write(stream.toString());
            writer.flush();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected void closeStream() throws IOException {
            writer.write("</stream:stream>");
            writer.flush();
        }
    }

    private class TCPXmppPacketReader extends PacketReader {

        private boolean startTLSReceived;

        private boolean startTLSRequired;

        private TCPXmppPacketReader() {
            super(XMPPConnection.this, "stream");
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected void init() {
            super.init();

            startTLSReceived = false;
            startTLSRequired = false;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected void doParsePackets(XmlPullParser parser) throws Exception {
            int eventType = parser.getEventType();
            boolean consumed = false;

            if (eventType == XmlPullParser.START_TAG) {
                // We found an opening stream. Record information about it, then notify
                // the connectionID lock so that the packet reader startup can finish.
                if (parser.getName().equals("stream")) {
                    // Ensure the correct jabber:client namespace is being used.
                    if ("jabber:client".equals(parser.getNamespace(null))) {
                        // Get the connection id.
                        for (int i=0; i<parser.getAttributeCount(); i++) {
                            if (parser.getAttributeName(i).equals("id")) {
                                String connectionID = parser.getAttributeValue(i);
                                String version = parser.getAttributeValue("", "version");
                                // Save the connectionID
                                XMPPConnection.this.connectionID = connectionID;
                                if (!"1.0".equals(version)) {
                                    // Notify that a stream has been opened if the
                                    // server is not XMPP 1.0 compliant otherwise make the
                                    // notification after TLS has been negotiated or if TLS
                                    // is not supported
                                    connected = true;
                                    releaseConnectionIDLock();
                                }
                            }
                            else if (parser.getAttributeName(i).equals("from")) {
                                // Use the server name that the server says that it is.
                                config.setServiceName(parser.getAttributeValue(i));
                            }
                        }
                    }
                }
                else if (parser.getName().equals("failure")) {
                    String namespace = parser.getNamespace(null);
                    if ("urn:ietf:params:xml:ns:xmpp-tls".equals(namespace)) {
                        // TLS negotiation has failed. The server will close the connection
                        throw new Exception("TLS negotiation has failed");
                    }
                    else if ("http://jabber.org/protocol/compress".equals(namespace)) {
                        // Stream compression has been denied. This is a recoverable
                        // situation. It is still possible to authenticate and
                        // use the connection but using an uncompressed connection
                        streamCompressionDenied();
                        // We do not want to trigger generic "failure" handler
                        // in super for this case.
                        consumed = true;
                    }
                }
                else if (parser.getName().equals("proceed")) {
                    // Secure the connection by negotiating TLS
                    proceedTLSReceived();
                }
                else if (parser.getName().equals("compressed")) {
                    // Server confirmed that it's possible to use stream compression. Start
                    // stream compression
                    startStreamCompression();
                    // Reset the state of the parser since a new stream element is going
                    // to be sent by the server
                    packetReader.resetParser();
                }
            }

            if (!consumed) {
                super.doParsePackets(parser);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected void doParseFeatures(XmlPullParser parser) throws Exception {

            super.doParseFeatures(parser);

            boolean lastLoop = false;
            int eventType = parser.getEventType();
            String name = parser.getName();

            if (eventType == XmlPullParser.START_TAG) {
                if ("starttls".equals(name)) {
                    startTLSReceived = true;
                }
                else if (parser.getName().equals("compression")) {
                    // The server supports stream compression
                    setAvailableCompressionMethods(
                        PacketParserUtils.parseCompressionMethods(parser));
                }
            }
            else if (eventType == XmlPullParser.END_TAG) {
                if (name.equals("starttls")) {
                    // Confirm the server that we want to use TLS
                    startTLSReceived(startTLSRequired);
                }
                else if (name.equals("required") && startTLSReceived) {
                    startTLSRequired = true;
                }
                else if (name.equals("features")) {
                    lastLoop = true;
                }
            }

            // This is the last loop of parsing "features" tag
            if (lastLoop) {
                // If TLS is required but the server doesn't offer it, disconnect
                // from the server and throw an error. First check if we've already negotiated TLS
                // and are secure, however (features get parsed a second time after TLS is established).
                if (!isSecureConnection()) {
                    if (!startTLSReceived && getConfiguration().getSecurityMode() ==
                        ConnectionConfiguration.SecurityMode.required) {
                        throw new XMPPException("Server does not support security (TLS), " +
                            "but security required by connection configuration.",
                            new XMPPError(XMPPError.Condition.forbidden));
                    }
                }

                // Release the lock after TLS has been negotiated or we are not interested in TLS
                if (!startTLSReceived || getConfiguration().getSecurityMode() ==
                        ConnectionConfiguration.SecurityMode.disabled) {
                    connected = true;
                    releaseConnectionIDLock();
                }

                startTLSReceived = false;
                startTLSReceived = false;
            }
        }
    }
}
