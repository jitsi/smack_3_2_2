/**
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
package org.jivesoftware.smackx.pubsub.packet;

import org.jivesoftware.smack.SmackConfiguration;
import org.jivesoftware.smack.Connection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Packet;

/**
 * Utility class for doing synchronous calls to the server.  Provides several
 * methods for sending a packet to the server and waiting for the reply.
 * 
 * @author Robin Collier
 */
final public class SyncPacketSend
{
	private SyncPacketSend()
	{	}
	
	static public Packet getReply(Connection connection, IQ packet, long timeout)
		throws XMPPException
	{
        return connection.createPacketCollectorAndSend(packet).nextResultOrThrow();
	}

	static public Packet getReply(Connection connection, IQ packet)
		throws XMPPException
	{
		return getReply(connection, packet, SmackConfiguration.getPacketReplyTimeout());
	}
}
