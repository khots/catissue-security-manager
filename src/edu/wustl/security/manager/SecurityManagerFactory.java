package edu.wustl.security.manager;

import edu.wustl.common.security.exceptions.SMException;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.locator.RoleGroupLocator;
import edu.wustl.security.locator.SecurityManagerPropertiesLocator;
/**
 * Factory to create an instance of ISecurityManager.
 * @author deepti_shelar
 *
 */
public class SecurityManagerFactory {

	/**
	 * logger Logger - Generic logger.
	 */
	private static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);
	ISecurityManager securityManager=null;
	public static ISecurityManager getSecurityManager(Class class1) throws SMException
	{
		
		Class className = null;
		ISecurityManager securityManager=null;
		String securityManagerClass = SecurityManagerPropertiesLocator.getInstance().getSecurityMgrClassName();
		if (securityManagerClass != null)
		{
			try {
				className = Class.forName(securityManagerClass);
				securityManager = (ISecurityManager)className.newInstance();
				RoleGroupLocator.init();
			} catch (ClassNotFoundException e) {
				String message = "Expected SecurityManager class name is not provided in properties file";
				logger.error(message);
				throw new SMException(message,e);
			} catch (InstantiationException e) {
				String message = "Can not instantiate class ";
				logger.error(message);
				throw new SMException("Can not instantiate class "+className,e);
			} catch (IllegalAccessException e) {
				String message = "Illegal access to the class ";
				logger.error(message);
				throw new SMException("Illegal access to the class "+className,e);
			}
		}
		return securityManager;
	}
}
