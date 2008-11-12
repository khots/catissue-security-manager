package edu.wustl.security.manager;


import edu.wustl.common.exception.ErrorKey;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.exception.SMException;
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
		if (securityManagerClass == null)
		{
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage("Could not get the className ");
			throw new SMException(defaultErrorKey,null,null);	
		}else
		{
			try {
				className = Class.forName(securityManagerClass);
				securityManager = (ISecurityManager)className.newInstance();
			} catch (ClassNotFoundException e) {
				String message = "Expected SecurityManager class name is not provided in properties file";
				logger.error(message);
				ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
				defaultErrorKey.setErrorMessage(message);
				throw new SMException(defaultErrorKey,e,null);	
			} catch (InstantiationException e) {
				String message = "Can not instantiate class ";
				logger.error(message);
				ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
				defaultErrorKey.setErrorMessage(message);
				throw new SMException(defaultErrorKey,e,null);	
			} catch (IllegalAccessException e) {
				String message = "Illegal access to the class ";
				logger.error(message);
				ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
				defaultErrorKey.setErrorMessage(message);
				throw new SMException(defaultErrorKey,e,null);	
			}
		}
		return securityManager;
	}
}
