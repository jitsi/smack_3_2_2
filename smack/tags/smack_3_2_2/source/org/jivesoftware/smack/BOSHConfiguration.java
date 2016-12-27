/**
 * $RCSfile$
 * $Revision: 3306 $
 * $Date: 2006-01-16 14:34:56 -0300 (Mon, 16 Jan 2006) $
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


import java.net.URI;
import java.net.URISyntaxException;

/**
 * BOSH configuration. A BOSH URL has to be set using
 * {@link #setBoshUrl(String)} and eventually proxy details
 * ({@link #setProxyEnabled(boolean)}, {@link #setProxyAddress(String)},
 * {@link #setProxyPort(int)}).
 */
public class BOSHConfiguration extends ConnectionConfiguration
{
    private String boshUrl;

    private boolean isProxyEnabled;

    private String proxyAddress;

    private int proxyPort;

    /**
     * Creates new <tt>BOSHConfiguration</tt>.
     *
     * @param serviceName the name of the service provided by an XMPP server
     * (name of the XMPP domain to which the connection will connect to).
     */
    public BOSHConfiguration(String serviceName) {
        // null and -1 are passed as host and port, as we don't want any DNS lookups for BOSH
        super(null, -1, serviceName);
    }

    /**
     * Tells whether or not proxy is enabled.
     *
     * @return <tt>true</tt> if proxy is enabled or <tt>false</tt> otherwise.
     */
    public boolean isProxyEnabled() {
        return isProxyEnabled;
    }

    /**
     * Enables/disabled proxy mode.
     *
     * @param isProxyEnabled <tt>true</tt> to enable proxy or <tt>false</tt> to
     * disable.
     */
    public void setProxyEnabled(boolean isProxyEnabled) {
        this.isProxyEnabled = isProxyEnabled;
    }

    /**
     * @return the proxy address which will be used by the BOSH connection
     */
    public String getProxyAddress() {
        return proxyAddress;
    }

    /**
     * Sets new proxy address
     * @param proxyAddress the proxy address to be used by the BOSH connection
     */
    public void setProxyAddress(String proxyAddress) {
        this.proxyAddress = proxyAddress;
    }

    /**
     * @return the port on which runs the proxy to which the BOSH connection
     * will try to connect to.
     */
    public int getProxyPort() {
        return proxyPort;
    }

    /**
     * Sets new proxy port.
     * @param proxyPort the port on which runs the proxy to which the BOSH
     * connection will try to connect to.
     */
    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }

    /**
     * Obtains the BOSH URL stored in this configuration instance.
     * @return a <tt>String</tt> with current BOSH URL.
     */
    public String getBoshUrl() {
        return boshUrl;
    }

    /**
     * Sets new BOSH URL.
     * @param boshUrl e.g. https://server.com/http-bind
     */
    public void setBoshUrl(String boshUrl) {
        this.boshUrl = boshUrl;
    }

    URI getURI() throws URISyntaxException {
        return boshUrl != null ? new URI(boshUrl) : null;
    }
}
