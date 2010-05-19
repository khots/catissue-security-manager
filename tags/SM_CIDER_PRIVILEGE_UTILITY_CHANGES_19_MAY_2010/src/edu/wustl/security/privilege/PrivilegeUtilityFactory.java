package edu.wustl.security.privilege;

import java.util.HashMap;
import java.util.Map;

import edu.wustl.common.util.logger.LoggerConfig;
import edu.wustl.security.exception.SMException;
import edu.wustl.security.locator.SecurityManagerPropertiesLocator;

/**
 *
 * @author niharika_sharma
 *
 */
public class PrivilegeUtilityFactory
{
    /**
     * logger Logger - Generic logger.
     */
    private static org.apache.log4j.Logger LOGGER = LoggerConfig.getConfiguredLogger(PrivilegeUtilityFactory.class);

    public static Map<String, PrivilegeUtility> privilegeUtilityMap=new HashMap<String, PrivilegeUtility>();

    public static PrivilegeUtility getPrivilegeUtility() throws SMException
    {
        final String appCtxName=SecurityManagerPropertiesLocator.getInstance().getApplicationCtxName();
        LOGGER.info("Getting the default PrivilegeUtility for appCtxNAme="+appCtxName);
        PrivilegeUtility utility=privilegeUtilityMap.get(appCtxName);
        if(utility==null)
        {
            LOGGER.info("Creating new PrivilegeUtility");
            utility=new PrivilegeUtility(appCtxName);
            privilegeUtilityMap.put(appCtxName, utility);
        }
        else
        {
            LOGGER.info("Taking PrivilegeUtility from cache");
        }
        return utility;
    }

    public static PrivilegeUtility getPrivilegeUtility(final String appCtxName) throws SMException
    {
        PrivilegeUtility utility=privilegeUtilityMap.get(appCtxName);
        LOGGER.info("Getting the PrivilegeUtility for appCtxNAme passed as argument="+appCtxName);
        if(utility==null)
        {
            LOGGER.info("Creating new PrivilegeUtility");
            utility=new PrivilegeUtility(appCtxName);
            privilegeUtilityMap.put(appCtxName, utility);
        }
        else
        {
            LOGGER.info("Taking PrivilegeUtility from cache");
        }
        return utility;
    }
}
