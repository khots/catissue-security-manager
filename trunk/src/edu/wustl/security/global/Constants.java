
package edu.wustl.security.global;

import java.util.HashMap;

/**
 * Class specific to constants used in SecurityManager.
 *  
 * @author deepti_shelar
 * */
public class Constants
{

	public static final int CLASS_LEVEL_SECURE_RETRIEVE = 1;
	public static final int OBJECT_LEVEL_SECURE_RETRIEVE = 2;
	public static final int INSECURE_RETRIEVE = 0;
	public static final String hashedOut = "##";
	public static final boolean PRIVILEGE_ASSIGN = true;
	public static final String CP_CLASS_NAME = 
		"edu.wustl.catissuecore.domain.CollectionProtocol";//CollectionProtocol.class.getName();
	public static final String DP_CLASS_NAME = 
		"edu.wustl.catissuecore.domain.DistributionProtocol";//DistributionProtocol.class.getName();
	public static final HashMap<String, String[]> STATIC_PROTECTION_GROUPS_FOR_OBJECT_TYPES
	= new HashMap<String, String[]>();
	public static final String SUPER_ADMIN_ROLE = "SUPER_ADMIN_ROLE";
	public static final String ADMIN_ROLE = "ADMIN_ROLE";
	public static final String SUPERVISOR_ROLE = "SUPERVISOR_ROLE";
	public static final String TECHNICIAN_ROLE = "TECHNICIAN_ROLE";
	public static final String PUBLIC_ROLE = "PUBLIC_ROLE";
	public static final String ADMIN_GRP_ID = "ADMIN_GRP_ID";
	public static final String SUPERVISOR_GRP_ID = "SUPERVISOR_GRP_ID";
	public static final String TECH_GRP_ID = "TECH_GRP_ID";
	public static final String PUBLIC_GROUP_ID = "PUBLIC_GROUP_ID";
	public static final String SUPER_ADM_GRP_ID = "SUPER_ADM_GRP_ID";
	public static final String SM_PROP_FILE = "SecurityManager.properties";
	public static final String APP_CTX_NAME = "application.context.name";
	public static final String SM_CLASSNAME = "class.name";
	public static final String ROLE_ADMIN = "Administrator";
	public static final String TECHNICIAN = "Technician";
	public static final String SUPERVISOR = "Supervisor";
	public static final String SCIENTIST = "Scientist";
	public static final String ROLE_SUPER_ADMIN = "SUPERADMINISTRATOR";
	public static final String ISCHECKPERMISSION = "isToCheckCSMPermission";
	public static final String ADMINISTRATOR = "Administrator";
	public static final String CATISSUE_SPECIMEN = "CATISSUE_SPECIMEN";
	public static final String PHI_ACCESS = "PHI_ACCESS";
	public static final String REGISTRATION = "REGISTRATION";
	public static final String READ_DENIED = "READ_DENIED";
	public static final String allowOperation = "allowOperation";
	public static final String BDATE_TAG_NAME = "IS_BIRTH_DATE";
	public static final String HASHED_OUT = "##";
}
