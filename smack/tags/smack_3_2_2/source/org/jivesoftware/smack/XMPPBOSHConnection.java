/**
 *
 * Copyright 2009 Jive Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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

import java.io.IOException;
import java.io.PipedReader;
import java.io.PipedWriter;
import java.io.Writer;
import java.net.URISyntaxException;
import java.util.logging.*;

import org.igniterealtime.jbosh.*;
import org.jivesoftware.smack.packet.Presence;

/**
 * Creates a connection to an XMPP server via HTTP binding.
 * This is specified in the XEP-0206: XMPP Over BOSH.
 *
 */
public class XMPPBOSHConnection extends AbstractConnection {

    private static final Logger LOGGER = Logger.getLogger(XMPPBOSHConnection.class.getName());

    /**
     * The XMPP Over Bosh namespace.
     */
    public static final String XMPP_BOSH_NS = "urn:xmpp:xbosh";

    /**
     * The BOSH namespace from XEP-0124.
     */
    public static final String BOSH_URI = "http://jabber.org/protocol/httpbind";

    /**
     * This is the name of the XML root element injected into
     * {@link #readerPipe}, so that it will encapsulate BOSH "body" element and
     * prevent from breaking the {@link org.xmlpull.v1.XmlPullParser}.
     */
    public static final String BOSH_STREAM_ROOT = "boshstream";

    /**
     * The used BOSH client from the jbosh library.
     */
    private BOSHClient client;

    /**
     * The readerPipe is used to pipe XML received over the BOSH connection to
     * the {@link PacketReader}.
     */
    private PipedWriter readerPipe;

    /**
     * The session ID for the BOSH session with the connection manager.
     */
    protected String sessionID = null;

    /**
     * Create a HTTP Binding connection to an XMPP server.
     *
     * @param config The configuration which is used for this connection.
     */
    public XMPPBOSHConnection(BOSHConfiguration config) {
        super(config);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void connectUsingConfiguration(ConnectionConfiguration c) throws XMPPException {
        BOSHConfiguration config = (BOSHConfiguration) c;

        try {
            // Ensure a clean starting state
            if (client != null) {
                client.close();
                client = null;
            }
            sessionID = null;

            // Initialize BOSH client
            BOSHClientConfig.Builder cfgBuilder = BOSHClientConfig.Builder
                .create(config.getURI(), config.getServiceName());
            if (config.isProxyEnabled()) {
                cfgBuilder.setProxy(config.getProxyAddress(), config.getProxyPort());
            }
            client = BOSHClient.create(cfgBuilder.build());

            client.addBOSHClientConnListener(new BOSHConnectionListener());
            client.addBOSHClientResponseListener(new BOSHPacketReader());
        } catch (URISyntaxException e) {
            throw new XMPPException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void initConnectionFailed(XMPPException ex) {
        if (client != null) {
            client.close();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void initReaderAndWriter() throws XMPPException {
        writer = new BOSHWriter();

        // Initialize a pipe for received raw data.
        try {
            readerPipe = new PipedWriter();
            reader = new PipedReader(readerPipe);

            readerPipe.write("<" + BOSH_STREAM_ROOT + ">");
        }
        catch (IOException e) {
            throw new XMPPException(e);
        }

        super.initReaderAndWriter();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected PacketReader createPacketReader() {
        return new PacketReader(this, BOSH_STREAM_ROOT);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected PacketWriter createPacketWriter() {
        return new BOSHPacketWriter();
    }

    /**
     * API NOT IMPLEMENTED IN BOSH
     */
    public boolean isSecureConnection() {
        // TODO: implement - should be true when HTTPS is used ?
        return false;
    }

    /**
     * API NOT IMPLEMENTED IN BOSH
     */
    public boolean isUsingCompression() {
        // TODO: Implement - jbosh seems to be capable of doing the compression
        return false;
    }

    /**
     * API NOT IMPLEMENTED IN BOSH
     */
    @Override
    protected boolean useCompression() {
        // TODO: Implement - jbosh seems to be capable of doing the compression
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void shutdown(Presence p) {

        super.shutdown(p);

        sessionID = null;

        if (this.client != null) {
            try {
                this.client.disconnect();
            }
            catch (BOSHException e) {
                LOGGER.log(Level.SEVERE, "Error disconnecting", e);
            }
            this.client = null;
        }

        // Close down the readers and writers.
        if (readerPipe != null) {
            try {
                // NOTE not sure if this is necessary
                readerPipe.write("</" + BOSH_STREAM_ROOT + ">");
                readerPipe.flush();

                readerPipe.close();
                readerPipe = null;
            }
            catch (Throwable ignore) { /* ignore */ }
        }
    }

    /**
     * Send a HTTP request to the connection manager with the provided body element.
     *
     * @param body the body which will be sent.
     */
    protected void send(ComposableBody body) throws BOSHException {
        if (body == null) {
            throw new NullPointerException("Body mustn't be null!");
        }
        if (sessionID != null) {
            body = body.rebuild().setAttribute(
                BodyQName.create(BOSH_URI, "sid"), sessionID).build();
        }

        if (LOGGER.isLoggable(Level.FINEST))
            LOGGER.finest("SEND: " + body.toXML());

        // FIXME messages sent through this method directly do not appear in the debugger
        client.send(body);
    }

    /**
     * A listener class which listen for a successfully established connection
     * and connection errors and notifies the BOSHConnection.
     *
     * @author Guenther Niess
     */
    private class BOSHConnectionListener implements BOSHClientConnListener {

        /**
         * Notify the BOSHConnection about connection state changes.
         * Process the connection listeners and try to login if the
         * connection was formerly authenticated and is now reconnected.
         */
        public void connectionEvent(BOSHClientConnEvent connEvent) {
            try {
                if (connEvent.isConnected()) {
                    connected = true;
                }
                else {
                    if (connEvent.isError()) {
                        // TODO Check why jbosh's getCause returns Throwable here. This is very
                        // unusual and should be avoided if possible
                        if (packetReader != null)
                            packetReader.notifyConnectionError(
                                new IOException(connEvent.getCause()));
                        else
                            LOGGER.log(Level.SEVERE, "BOSH ERROR", connEvent.getCause());
                    }
                    connected = false;
                }
            }
            finally {
                // If the connection happens fast the packetReader will be null,
                // but it will check the flag before sleeping on the semaphore.
                if (packetReader != null) {
                    packetReader.releaseConnectionIDLock();
                }
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    protected void onSuccessReceived() throws IOException {
        packetWriter.openStream();
    }

    class BOSHPacketWriter extends PacketWriter {

        /**
         * Creates a new packet writer with the specified connection.
         */
        BOSHPacketWriter() {
            super(XMPPBOSHConnection.this, true);
        }

        @Override
        protected void openStream() throws IOException {
            // Send the session creation request
            // It doesn't go through writer, because it would get wrapped into
            // another "body"
            try {
                ComposableBody.Builder body = ComposableBody.builder();

                body.setNamespaceDefinition("xmpp", XMPP_BOSH_NS);
                body.setAttribute(
                    BodyQName.createWithPrefix(
                        XMPP_BOSH_NS, "version", "xmpp"), "1.0");
                if (connected) {
                    body.setAttribute(
                        BodyQName.createWithPrefix(
                            XMPPBOSHConnection.XMPP_BOSH_NS, "restart", "xmpp"),
                        "true");
                }
                body.setAttribute(
                    BodyQName.create(
                        XMPPBOSHConnection.BOSH_URI, "to"),
                    config.getServiceName());

                send(body.build());
            }
            catch (BOSHException e) {
                throw new IOException(e);
            }
        }

        @Override
        protected void closeStream() throws IOException {
            // BOSH does nothing when stream ends
        }
    }

    /**
     * Listens for XML traffic from the BOSH connection manager and pushes that
     * to the {@link #readerPipe}, so that the {@link PacketReader} can parse
     * and interpret it. The pipe was used to preserve the same method which
     * {@link XMPPConnection} uses for both the packet parsing and debugger's
     * pipeline implementation.
     *
     * @author Guenther Niess
     * @author Pawel Domas
     */
    private class BOSHPacketReader implements BOSHClientResponseListener {

        /**
         * Parse the received packets and notify the corresponding connection.
         *
         * @param event the BOSH client response which includes the received packet.
         */
        public void responseReceived(BOSHMessageEvent event) {
            AbstractBody body = event.getBody();
            if (body != null) {

                if (LOGGER.isLoggable(Level.FINEST))
                    LOGGER.finest("RECVD: " + body.toXML());

                try {
                    if (sessionID == null) {
                        sessionID
                            = body.getAttribute(
                                BodyQName.create(
                                    XMPPBOSHConnection.BOSH_URI, "sid"));
                    }
                    if (connectionID == null) {
                        connectionID
                            = body.getAttribute(
                                BodyQName.create(
                                    XMPPBOSHConnection.BOSH_URI, "authid"));
                    }

                    readerPipe.write(body.toXML());
                    readerPipe.flush();
                }
                catch (IOException e) {
                    if (isConnected()) {
                        packetReader.notifyConnectionError(e);
                    }
                }
            }
        }
    }

    /**
     * It's a writer to which {@link PacketWriter} writes packets. Packets are
     * sent in a BOSH "body" when {@link PacketWriter} calls {@link #flush()}.
     */
    private class BOSHWriter extends Writer {

        private StringBuilder buffer = new StringBuilder();

        @Override
        public void write(char[] cbuf, int off, int len) throws IOException {
            if (buffer == null)
                throw new IOException("BOSHWriter is closed");

            buffer.append(cbuf, off, len);
        }

        @Override
        public void flush() throws IOException {
            if (buffer == null)
                throw new IOException("BOSHWriter is closed");

            try {
                String toSend = this.buffer.toString();
                this.buffer = new StringBuilder();

                ComposableBody body
                    = ComposableBody.builder().setPayloadXML(toSend).build();

                send(body);
            }
            catch (BOSHException e) {
                // Wrap into IO
                throw new IOException(e);
            }
        }

        @Override
        public void close() throws IOException {
            buffer = null;
        }
    }
}