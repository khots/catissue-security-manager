package edu.wustl.security.manager;


import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.exception.SMException;
import edu.wustl.security.global.Utility;
import edu.wustl.security.locator.SecurityManagerPropertiesLocator;
/**
 * Factory to create an instance of ISecurityManager.
 * @author deepti_shelar
 *
 */
public class SecurityManagerFactory
{
	/**
	 * logger Logger - Generic logger.
	 */
	private static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);
	public static ISecurityManager getSecurityManager(final Class class1) 
	throws SMException
	{
		String smClassName = SecurityManagerPropertiesLocator.getInstance().getSecurityMgrClassName();
		ISecurityManager securityManager = null;
		if (smClassName == null)
		{
			Utility.getInstance().throwException(null, "Could not get the className ");
		}else
		{
			securityManager = getSMInstance(smClassName);
		}
		return securityManager;
	}
	/**
	 * @param smClassName
	 * @throws SMException
	 */
	private static ISecurityManager getSMInstance(String smClassName) throws SMException {
		ISecurityManager securityManager = null;
		try {
			Class className = Class.forName(smClassName);
			securityManager = (ISecurityManager)className.newInstance();
		} catch (ClassNotFoundException e) {
			String message = "Expected SecurityManager class name is not provided in properties file";
			Utility.getInstance().throwException(e,message);
		} catch (InstantiationException e) {
			String message = "Can not instantiate class ";
			Utility.getInstance().throwException(e,message);
		} catch (IllegalAccessException e) {
			String message = "Illegal access to the class ";
			Utility.getInstance().throwException(e,message);
		}
		return securityManager;
	}
}
