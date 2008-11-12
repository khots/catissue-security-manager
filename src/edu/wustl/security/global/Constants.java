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
	public static final String CP_CLASS_NAME = "edu.wustl.catissuecore.domain.CollectionProtocol";//CollectionProtocol.class.getName();
	public static final String DP_CLASS_NAME = "edu.wustl.catissuecore.domain.DistributionProtocol";//DistributionProtocol.class.getName();
	public static final  HashMap<String, String[]> 
	STATIC_PROTECTION_GROUPS_FOR_OBJECT_TYPES = new HashMap<String, String[]>();
	public static final String SUPER_ADMINISTRATOR_ROLE = "SUPER_ADMINISTRATOR_ROLE";
	public static final String ADMINISTRATOR_ROLE = "ADMINISTRATOR_ROLE";
	public static final String SUPERVISOR_ROLE = "SUPERVISOR_ROLE";
	public static final String TECHNICIAN_ROLE = "TECHNICIAN_ROLE";
	public static final String PUBLIC_ROLE = "PUBLIC_ROLE";
	public static final String ADMINISTRATOR_GROUP_ID = "ADMINISTRATOR_GROUP_ID";
	public static final String SUPERVISOR_GROUP_ID = "SUPERVISOR_GROUP_ID";
	public static final String TECHNICIAN_GROUP_ID = "TECHNICIAN_GROUP_ID";
	public static final String PUBLIC_GROUP_ID = "PUBLIC_GROUP_ID";
	public static final String SUPER_ADMINISTRATOR_GROUP_ID = "SUPER_ADMINISTRATOR_GROUP_ID";
    public static final String SECURITY_MANAGER_PROP_FILE = "SecurityManager.properties";
    public static final String APPLN_CONTEXT_NAME = "application.context.name";
    public static final String SECURITY_MANAGER_CLASSNAME = "class.name";
    public static final String ROLE_ADMINISTRATOR="Administrator";
    public static final String TECHNICIAN = "Technician";
	public static final String SUPERVISOR = "Supervisor";
	public static final String SCIENTIST = "Scientist";
	public static final String ROLE_SUPER_ADMINISTRATOR="SUPERADMINISTRATOR";
	public static final String ISCHECKPERMISSION="isToCheckCSMPermission";
	public static final String ADMINISTRATOR = "Administrator";
	public static final String CATISSUE_SPECIMEN = "CATISSUE_SPECIMEN";
	public static final String PHI_ACCESS = "PHI_ACCESS";
	public static final String REGISTRATION = "REGISTRATION";
	public static final String READ_DENIED = "READ_DENIED";
	public static final String allowOperation = "allowOperation";
	public static final String BIRTH_DATE_TAG_NAME = "IS_BIRTH_DATE";
}


