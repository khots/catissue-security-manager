
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
	 * logger -Generic Logger
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
		logger.debug(mess, exc);
		ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
		defaultErrorKey.setErrorMessage(mess);
		throw new SMException(defaultErrorKey, exc, null);
	}
	/* Added By Rukhsana
	 * Added list of objects on which read denied has to be checked while filtration of result for csm-query performance.
	 * A map that contains entity name as key and sql to get Main_Protocol_Object (Collection protocol, Clinical Study) Ids for that entity id as value for csm-query performance.
	 * Reading the above values from a properties file to make query module application independent
	 
	public static void setReadDeniedAndEntitySqlMap()
	{
		List<String> queryReadDeniedObjectsList = new ArrayList<String>();
		Map<String, String> entityCSSqlMap = new HashMap<String, String>();
		String mainProtocolClassName = "";
		String validatorClassname = "";
		File file = new File(Variables.applicationHome + System.getProperty("file.separator")
				+ "WEB-INF" + System.getProperty("file.separator") + "classes"
				+ System.getProperty("file.separator") + Constants.CSM_PROPERTY_FILE);
		if (file.exists())
		{
			Properties csmPropertyFile = new Properties();
			try
			{

				csmPropertyFile.load(new FileInputStream(file));
				mainProtocolClassName = csmPropertyFile.getProperty(Constants.MAIN_PROTOCOL_OBJECT);
				validatorClassname = csmPropertyFile.getProperty(Constants.VALIDATOR_CLASSNAME);
				String readdenied = csmPropertyFile.getProperty(Constants.READ_DENIED_OBJECTS);
				String[] readDeniedObjects = readdenied.split(",");
				for (int i = 0; i < readDeniedObjects.length; i++)
				{
					queryReadDeniedObjectsList.add(readDeniedObjects[i]);
					if (csmPropertyFile.getProperty(readDeniedObjects[i]) != null)
						entityCSSqlMap.put(readDeniedObjects[i], csmPropertyFile
								.getProperty(readDeniedObjects[i]));
				}
			}
			catch (FileNotFoundException e)
			{
				Logger.out.debug("csm.properties not found");
				e.printStackTrace();
			}
			catch (IOException e)
			{
				Logger.out.debug("Exception occured while reading csm.properties");
				e.printStackTrace();
			}
			Variables.mainProtocolObject = mainProtocolClassName;
			Variables.queryReadDeniedObjectList.addAll(queryReadDeniedObjectsList);
			Variables.entityCPSqlMap.putAll(entityCSSqlMap);
			Variables.validatorClassname = validatorClassname;
		}

	}*/

}
