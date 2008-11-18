
package edu.wustl.security.global;

/**
 * Interface for storing the names of Permissions that are defined
 * in the authorization database.
 *
 *
 * @author Brian Husted
 */
public interface Permissions
{

	/**
	 * READ String read permission.
	 */
	public static final String READ = "READ";
	/**
	 * READ_DENIED String read denied permission.
	 */
	public static final String READ_DENIED = "READ_DENIED";
	/**
	 * UPDATE String update permission.
	 */
	public static final String UPDATE = "UPDATE";
	/**
	 * DELETE String delete permission.
	 */
	public static final String DELETE = "DELETE";
	/**
	 * CREATE String create permission.
	 */
	public static final String CREATE = "CREATE";
	/**
	 * EXECUTE String execute permission.
	 */
	public static final String EXECUTE = "EXECUTE";
	/**
	 * USE String use permission.
	 */
	public static final String USE = "USE";
	/**
	 * ASSIGN_READ String assign read permission.
	 */
	public static final String ASSIGN_READ = "ASSIGN_READ";
	/**
	 * ASSIGN_USE String assign use permission.
	 */
	public static final String ASSIGN_USE = "ASSIGN_USE";
	/**
	 * IDENTIFIED_DATA_ACCESS String identifying data access permission.
	 */
	public static final String IDENTIFIED_DATA_ACCESS = "IDENTIFIED_DATA_ACCESS";
	/**
	 * USER_PROVISIONING String provisioning user permission.
	 */
	public static final String USER_PROVISIONING = "USER_PROVISIONING";
	/**
	 * REPOSITORY_ADMINISTRATION String repository administration permission.
	 */
	public static final String REPOSITORY_ADMINISTRATION = "REPOSITORY_ADMINISTRATION";
	/**
	 * STORAGE_ADMINISTRATION String storage administration permission.
	 */
	public static final String STORAGE_ADMINISTRATION = "STORAGE_ADMINISTRATION";
	/**
	 * PROTOCOL_ADMINISTRATION String protocol administration permission.
	 */
	public static final String PROTOCOL_ADMINISTRATION = "PROTOCOL_ADMINISTRATION";
	/**
	 * DEFINE_ANNOTATION String defining annotation permission.
	 */
	public static final String DEFINE_ANNOTATION = "DEFINE_ANNOTATION";
	/**
	 * REGISTRATION String registration permission.
	 */
	public static final String REGISTRATION = "REGISTRATION";
	/**
	 * SPECIMEN_ACCESSION String specimen accession permission.
	 */
	public static final String SPECIMEN_ACCESSION = "SPECIMEN_ACCESSION";
	/**
	 * DISTRIBUTION String distribution permission.
	 */
	public static final String DISTRIBUTION = "DISTRIBUTION";
	/**
	 * QUERY String permission for query.
	 */
	public static final String QUERY = "QUERY";
	// public static final String PHI = "PHI";
	/**
	 * PHI String phi access permission.
	 */
	public static final String PHI = "PHI_ACCESS";
	/**
	 * PARTICIPANT_SCG_ANNOTATION String annotation for scg participant permission.
	 */
	public static final String PARTICIPANT_SCG_ANNOTATION = "PARTICIPANT_SCG_ANNOTATION";
	/**
	 * SPECIMEN_ANNOTATION String annotation for specimen permission.
	 */
	public static final String SPECIMEN_ANNOTATION = "SPECIMEN_ANNOTATION";
	/**
	 * SPECIMEN_PROCESSING String specimen processing permission.
	 */
	public static final String SPECIMEN_PROCESSING = "SPECIMEN_PROCESSING";
	/**
	 * SPECIMEN_STORAGE String specimen storage permission.
	 */
	public static final String SPECIMEN_STORAGE = "SPECIMEN_STORAGE";
	/**
	 * GENERAL_SITE_ADMINISTRATION String general site administration permission.
	 */
	public static final String GENERAL_SITE_ADMINISTRATION = "GENERAL_SITE_ADMINISTRATION";
	/**
	 */
	public static final String GENERAL_ADMINISTRATION = "GENERAL_ADMINISTRATION";
	/**
	 * SHIPMENT_PROCESSING String shipment processing permission.
	 */
	public static final String SHIPMENT_PROCESSING = "SHIPMENT_PROCESSING";

}
