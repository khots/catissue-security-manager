
package edu.wustl.common.security;

import edu.wustl.common.beans.SessionDataBean;

public interface IValidator
{

	public boolean hasPrivilegeToView(SessionDataBean sessionDataBean, String baseObjectId,
			String privilegeName);

	public boolean hasPrivilegeToViewGlobalParticipant(SessionDataBean sessionDataBean);

}
