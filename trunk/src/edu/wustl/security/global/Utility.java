package edu.wustl.security.global;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import edu.wustl.common.beans.SessionDataBean;
import edu.wustl.common.dao.DAOFactory;
import edu.wustl.common.dao.JDBCDAO;
import edu.wustl.common.util.dbmanager.DAOException;
import edu.wustl.common.util.global.Constants;
import edu.wustl.common.util.global.Variables;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.privilege.PrivilegeType;
/**
 * Utility methods required in SecurityManager
 * @author deepti_shelar
 *
 */
public class Utility {
	/**
	 * logger -Generic Logger
	 */
	private static org.apache.log4j.Logger logger = Logger.getLogger(Utility.class);

	
	/**
	 * TO get the PrivilegeType of an Entity.
	 * @param tagKeyValueMap The reference to Entity.
	 * @return appropriate PrivilegeType of the given Entity.
	 */
	public static PrivilegeType getPrivilegeType(Map<String, String> tagKeyValueMap)
	{
		PrivilegeType pType = PrivilegeType.ClassLevel;
		if(tagKeyValueMap.containsKey(Constants.PRIVILEGE_TAG_NAME))
		{
			String tagVal = tagKeyValueMap.get(Constants.PRIVILEGE_TAG_NAME);
			pType =  PrivilegeType.getPrivilegeType(Integer.parseInt(tagVal));
		}
		return pType;
	}
	/**
	 * 
	 * @param tagKeyValueMap
	 * @return
	 */
	 public static boolean getIsBirthDate(Map<String, String> tagKeyValueMap)
	    {    
		 boolean isBirthDate = false;
	       if(tagKeyValueMap.containsKey(edu.wustl.security.global.Constants.BIRTH_DATE_TAG_NAME)) {  
	    	   String tagValue = tagKeyValueMap.get(edu.wustl.security.global.Constants.BIRTH_DATE_TAG_NAME);
	            if (tagValue.equalsIgnoreCase(Constants.TRUE))
	            {
	            	isBirthDate =  true;
	            }
	        }
	        return isBirthDate;
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