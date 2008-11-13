
package edu.wustl.security.privilege;

import edu.wustl.common.beans.SessionDataBean;

public interface IValidator
{

	boolean hasPrivilegeToView(SessionDataBean sessionDataBean, String baseObjectId,
			String privilegeName);

	boolean hasPrivilegeToViewGlobalParticipant(SessionDataBean sessionDataBean);

}
