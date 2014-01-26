<?

error_reporting(E_ALL); // Debug

// First check if class and interface has already been defined.
if (!class_exists('AuthPlugin'))
{
    /**
     * Auth Plug-in
     *
     */
    require_once __DIR__.'/../../includes/AuthPlugin.php';

}

require_once __DIR__.'/MultiAuthBridge.php';
require_once __DIR__.'/PasswordHash.php';
require_once __DIR__.'/Connection.php';