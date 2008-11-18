/**
 *
 */

package edu.wustl.security.global;

/**
 * Interface for storing the roles of users.
 * @author Srinivasarao_Vassadi
 *
 */
public interface Roles
{

	/**
	 * ADMINISTRATOR String role of administrator.
	 */
	public static final String ADMINISTRATOR = "ADMINISTRATOR";
	/**
	 * SUPERVISOR String role of supervisor.
	 */
	public static final String SUPERVISOR = "SUPERVISOR";
	/**
	 * TECHNICIAN String role of technician.
	 */
	public static final String TECHNICIAN = "TECHNICIAN";
	/**
	 * SCIENTIST String   scientist.
	 */
	public static final String SCIENTIST = "SCIENTIST";
	/**
	 * READ_ONLY String read only.
	 */
	public static final String READ_ONLY = "READ_ONLY";
	/**
	 * USE_ONLY String use only.
	 */
	public static final String USE_ONLY = "USE_ONLY";
	/**
	 * UPDATE_ONLY String update only.
	 */
	public static final String UPDATE_ONLY = "UPDATE_ONLY";

}
