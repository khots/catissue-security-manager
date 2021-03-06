/*L
 *  Copyright Washington University in St. Louis
 *  Copyright SemanticBits
 *  Copyright Persistent Systems
 *  Copyright Krishagni
 *
 *  Distributed under the OSI-approved BSD 3-Clause License.
 *  See http://ncip.github.com/catissue-security-manager/LICENSE.txt for details.
 */

package edu.wustl.security.exception;

import edu.wustl.common.exception.ApplicationException;
import edu.wustl.common.exception.ErrorKey;

/**
 *@author Aarti Sharma
 *@version 1.0
 */
public class SMException extends ApplicationException
{
	/**
	 *
	 * @param errorKey eror key
	 * @param exception exc
	 * @param msgValues meg
	 */
	public SMException(final ErrorKey errorKey, final Exception exception, final String msgValues)
	{
		super(errorKey, exception, msgValues);
	}

	/**
	 * serial version id.
	 */
	private static final long serialVersionUID = 1998965888442573900L;
}
