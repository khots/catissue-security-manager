package edu.wustl.security.locator;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import edu.wustl.common.util.dbmanager.DBUtil;
import edu.wustl.common.util.global.Constants;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.manager.SecurityManager;
/**
 * Reads the SecurityManager.properties file and loads properties to be referred by SecurityManager.
 * @author deepti_shelar
 *
 */
public class SecurityManagerPropertiesLocator {

	/**
	 * logger Logger - Generic logger.
	 */
	private static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);

	private static Properties SECURITY_MANAGER_PROP;
	public static String APPLICATION_CONTEXT_NAME = null;	
	public static String SECURITY_MANAGER_CLASS = null;
	public static void init() {
		InputStream inputStream = DBUtil.class.getClassLoader().getResourceAsStream(
				Constants.SECURITY_MANAGER_PROP_FILE);
		SECURITY_MANAGER_PROP = new Properties();
		try
		{
			SECURITY_MANAGER_PROP.load(inputStream);
			inputStream.close();
			APPLICATION_CONTEXT_NAME = SECURITY_MANAGER_PROP.getProperty(Constants.APPLN_CONTEXT_NAME);
			SECURITY_MANAGER_CLASS = SECURITY_MANAGER_PROP.getProperty(Constants.SECURITY_MANAGER_CLASSNAME);
		}
		catch (IOException exception)
		{
			logger.warn("Not able to initialize Security Manager Properties.", exception);
		}
	}
}
