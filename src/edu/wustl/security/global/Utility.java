
package edu.wustl.security.global;

import java.util.Map;

import edu.wustl.common.exception.ErrorKey;
import edu.wustl.common.util.global.Constants;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.exception.SMException;
import edu.wustl.security.privilege.PrivilegeManager;
import edu.wustl.security.privilege.PrivilegeType;

/**
 * Utility methods required in SecurityManager
 * @author deepti_shelar
 *
 */
public final class Utility
{

	/**
	 * logger -Generic Logger.
	 */

	private static org.apache.log4j.Logger logger = Logger.getLogger(PrivilegeManager.class);

	private static Utility util = new Utility();;

	private Utility()
	{

	}

	public static Utility getInstance()
	{
		return util;
	}

	/**
	 * TO get the PrivilegeType of an Entity.
	 * @param tagKeyValueMap The reference to Entity.
	 * @return appropriate PrivilegeType of the given Entity.
	 */
	public PrivilegeType getPrivilegeType(final Map<String, String> tagKeyValueMap)
	{
		PrivilegeType pType = PrivilegeType.ClassLevel;
		if (tagKeyValueMap.containsKey(Constants.PRIVILEGE_TAG_NAME))
		{
			String tagVal = tagKeyValueMap.get(Constants.PRIVILEGE_TAG_NAME);
			pType = PrivilegeType.getPrivilegeType(Integer.parseInt(tagVal));
		}
		return pType;
	}

	/**
	 * 
	 * @param tagKeyValueMap
	 * @return
	 */
	public boolean getIsBirthDate(final Map<String, String> tagKeyValueMap)
	{
		boolean isBirthDate = false;
		if (tagKeyValueMap.containsKey(edu.wustl.security.global.Constants.BDATE_TAG_NAME))
		{
			String tagValue = tagKeyValueMap
					.get(edu.wustl.security.global.Constants.BDATE_TAG_NAME);
			if (tagValue.equalsIgnoreCase(Constants.TRUE))
			{
				isBirthDate = true;
			}
		}
		return isBirthDate;
	}

	/**
	 * 
	 * Called when we need to throw SMException
	 * @param exc exception
	 * @param mess message to be shown on error
	 * @throws SMException exception
	 */
	public void throwSMException(Exception exc, String mess) throws SMException
	{
		logger.error(mess, exc);
		ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
		defaultErrorKey.setErrorMessage(mess);
		throw new SMException(defaultErrorKey, exc, null);
	}
}
