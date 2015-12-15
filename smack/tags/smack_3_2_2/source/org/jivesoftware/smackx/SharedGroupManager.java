package org.jivesoftware.smackx;

import org.jivesoftware.smack.Connection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smackx.packet.SharedGroupsInfo;

import java.util.List;

/**
 * A SharedGroupManager provides services for discovering the shared groups where a user belongs.<p>
 *
 * Important note: This functionality is not part of the XMPP spec and it will only work
 * with Wildfire.
 *
 * @author Gaston Dombiak
 */
public class SharedGroupManager {

    /**
     * Returns the collection that will contain the name of the shared groups where the user
     * logged in with the specified session belongs.
     *
     * @param connection connection to use to get the user's shared groups.
     * @return collection with the shared groups' name of the logged user.
     */
    public static List getSharedGroups(Connection connection) throws XMPPException {
        // Discover the shared groups of the logged user
        SharedGroupsInfo info = new SharedGroupsInfo();
        info.setType(IQ.Type.GET);

        return ((SharedGroupsInfo) connection.createPacketCollectorAndSend(info)
                    .nextResultOrThrow()).getGroups();
    }
}
