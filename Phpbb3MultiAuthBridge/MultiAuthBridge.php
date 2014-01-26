<?php

namespace Seyon\Phpbb3MultiAuthBridge;

/**
 * This is a extended version of https://github.com/Digitalroot/MediaWiki_PHPBB_Auth/tree/v3.0.3
 * This Version can enable multiple PHPBB3 Systems as Auth provider
 * So you can share your wiki with more than 1 PHPBB Community
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @package MediaWiki
 * @subpackage Auth_phpBB_multiple
 * @author Christian Wielath
 * @copyright 2014 Christian Wielath
 * @license http://www.gnu.org/copyleft/gpl.html
 * @link https://github.com/seyon
 * @version 1.0
 *
 */
class MultiAuthBridge extends \AuthPlugin {

    /**
     * This turns on and off printing of debug information to the screen.
     *
     * @var bool
     */
    private $debug = false;

    /**
     * Message user sees when logging in.
     *
     * @var string
     */
    private $loginError = '<b>You need a phpBB account to login.</b><br />';

    /**
     * Text user sees when they login and are not a member of the wiki group.
     *
     * @var string
     */
    private $authError = 'You are not a member of the required phpBB group.';

    /**
     * UserID of our current user.
     *
     * @var int
     */
    private $userId;
    
    protected $connections = array();
    
    /**
     *
     * @var Connection
     */
    protected $foundConnection;

    /**
     * Constructor
     *
     * @param array $aConfig
     */
    function __construct() {
        // Set some values phpBB needs.
        define('IN_PHPBB', true); // We are secure.
        //
        // Set some MediaWiki Values
        // This requires a user be logged into the wiki to make changes.
        $GLOBALS['wgGroupPermissions']['*']['edit'] = false;

        // Specify who may create new accounts:
        $GLOBALS['wgGroupPermissions']['*']['createaccount'] = false;

        // Load Hooks
        $GLOBALS['wgHooks']['UserLoginForm'][] = array($this, 'onUserLoginForm', false);
        $GLOBALS['wgHooks']['UserLoginComplete'][] = $this;
        $GLOBALS['wgHooks']['UserLogout'][] = $this;
    }
    
    public function setLoginErrorMessage($message){
        $this->loginError = $message;
    }
    
    public function setAuthErrorMessage($message){
        $this->authError = $message;
    }

    /**
     * @return Connection
     */
    public function getFoundConnection(){
        return $this->foundConnection;
    }
    /**
     * Allows the printing of the object.
     *
     */
    public function __toString() {
        echo '<pre>';
        print_r($this);
        echo '</pre>';
    }

    /**
     * Add a user to the external authentication database.
     * Return true if successful.
     *
     * NOTE: We are not allowed to add users to phpBB from the
     * wiki so this always returns false.
     *
     * @param User $user - only the name should be assumed valid at this point
     * @param string $password
     * @param string $email
     * @param string $realname
     * @return bool
     * @access public
     */
    public function addUser($user, $password, $email = '', $realname = '') {
        return false;
    }

    /**
     * Can users change their passwords?
     *
     * @return bool
     */
    public function allowPasswordChange() {
        return true;
    }

    /**
     * Check if a username+password pair is a valid login.
     * The name will be normalized to MediaWiki's requirements, so
     * you might need to munge it (for instance, for lowercase initial
     * letters).
     *
     * @param string $username
     * @param string $password
     * @return bool
     * @access public
     * @todo Check if the password is being changed when it contains a slash or an escape char.
     */
    public function authenticate($username, $password) {
        
        $connections = $this->getConnections();
        
        foreach($connections as $connection){
            
            // Connect to the database.
            $fresMySQLConnection    = $this->connect($connection);

            $username               = $this->utf8($username); // Convert to UTF8
            $username               = $this->removeConnectionUsernamePrefix($connection, $username);
            //
            // Check Database for username and password.
            $fstrMySQLQuery = sprintf("SELECT `user_id`, `username_clean`, `user_password`
                              FROM `%s`
                              WHERE `username_clean` = '%s'
                              LIMIT 1", $connection->getUserTable(), mysql_real_escape_string($username, $fresMySQLConnection));

            // Query Database.
            $fresMySQLResult = mysql_query($fstrMySQLQuery, $fresMySQLConnection) or die($this->mySQLError('Unable to view external table'));

            while ($faryMySQLResult = mysql_fetch_assoc($fresMySQLResult)) {
                // Use new phpass class
                $PasswordHasher = new PasswordHash(8, TRUE);

                // Print the hash of the password entered by the user and the
                // password hash from the database to the screen.
                // While this will display its not effective anymore.
                if ($this->debug) {
                    //print md5($password) . ':' . $faryMySQLResult['user_password'] . '<br />'; // Debug
                    print $PasswordHasher->HashPassword($password) . ':' . $faryMySQLResult['user_password'] . '<br />'; // Debug
                }

                /**
                 * Check if password submited matches the PHPBB password.
                 * Also check if user is a member of the phpbb group 'wiki'.
                 */
                if ($PasswordHasher->CheckPassword($password, $faryMySQLResult['user_password']) && $this->isMemberOfWikiGroup($username, $connection)) {
                    $this->userId = $faryMySQLResult['user_id'];
                    $this->foundConnection = $connection;
                    return true;
                }
            }
        }
        
        return false;
    }

    public function addPHPBBSystem($host, $user, $password, $database, $prefix = 'phpbb_', $groups = array(), $usernamePrefix = ''){
        
        foreach($this->connections as $conn){
            if($conn->getUsernamePrefix() == $usernamePrefix){
                throw new \Exception('The Usernameprefix ['.$usernamePrefix.'] is already definied!');
            }
        }
        
        $connection = new Connection();
        $connection->setHost($host);
        $connection->setUser($user);
        $connection->setPassword($password);
        $connection->setDatabase($database);
        $connection->setPrefix($prefix);
        $connection->setGroups($groups);
        $connection->setUsernameprefix($usernamePrefix);
        $this->connections[] = $connection;
    }
    
    public function getConnections(){
        return $this->connections;
    }
    
    /**
     * Return true if the wiki should create a new local account automatically
     * when asked to login a user who doesn't exist locally but does in the
     * external auth database.
     *
     * If you don't automatically create accounts, you must still create
     * accounts in some way. It's not possible to authenticate without
     * a local account.
     *
     * This is just a question, and shouldn't perform any actions.
     *
     * NOTE: I have set this to true to allow the wiki to create accounts.
     *       Without an accout in the wiki database a user will never be
     *       able to login and use the wiki. I think the password does not
     *       matter as long as authenticate() returns true.
     *
     * @return bool
     * @access public
     */
    public function autoCreate() {
        return true;
    }

    /**
     * Check to see if external accounts can be created.
     * Return true if external accounts can be created.
     *
     * NOTE: We are not allowed to add users to phpBB from the
     * wiki so this always returns false.
     *
     * @return bool
     * @access public
     */
    public function canCreateAccounts() {
        return false;
    }

    /**
     * Connect to the database. All of these settings are from the
     * LocalSettings.php file. This assumes that the PHPBB uses the same
     * database/server as the wiki.
     *
     * {@source }
     * @return resource
     */
    private function connect(Connection $connection) {
        
        // Connect to database. I supress the error here.
        $fresMySQLConnection = mysql_connect($connection->getHost(), $connection->getUser(), $connection->getPassword(), true);

        // Check if we are connected to the database.
        if (!$fresMySQLConnection) {
            $this->mySQLError('There was a problem when connecting to the phpBB database.<br />' .
                    'Check your Host('.$connection->getHost().'), Username('.$connection->getUser().'), and Password('.$connection->getPassword().') settings.<br />');
        }

        // Select Database
        $db_selected = mysql_select_db($connection->getDatabase(), $fresMySQLConnection);

        // Check if we were able to select the database.
        if (!$db_selected) {
            $this->mySQLError('There was a problem when connecting to the phpBB database.<br />' .
                    'The database ' . $connection->getDatabase() . ' was not found.<br />');
        }

        mysql_query("SET NAMES 'utf8'", $fresMySQLConnection); // This is so utf8 usernames work. Needed for MySQL 4.1

        return $fresMySQLConnection;
    }

    /**
     * This turns on debugging
     *
     */
    public function EnableDebug() {
        $this->debug = true;
        return;
    }

    /**
     * If you want to munge the case of an account name before the final
     * check, now is your chance.
     *
     * @return string
     */
    public function getCanonicalName($username) {
        
        if($this->getFoundConnection()){
            $connections = array($this->getFoundConnection());
        } else {
            $connections = $this->getConnections();
        }
        
        foreach($connections as $connection){
            
            // Connect to the database.
            $fresMySQLConnection = $this->connect($connection);

            $username   = $this->utf8($username); // Convert to UTF8
            $username   = $this->removeConnectionUsernamePrefix($connection, $username);
            
            // Check Database for username. We will return the correct casing of the name.
            $fstrMySQLQuery = sprintf("SELECT `username_clean`
                              FROM `%s`
                              WHERE `username_clean` = '%s'
                              LIMIT 1", $connection->getUserTable(), mysql_real_escape_string($username, $fresMySQLConnection));

            // Query Database.
            $fresMySQLResult = mysql_query($fstrMySQLQuery, $fresMySQLConnection) or die($this->mySQLError('Unable to view external table'));

            while ($faryMySQLResult = mysql_fetch_assoc($fresMySQLResult)) {
                return $connection->getUsernamePrefix().ucfirst($faryMySQLResult['username_clean']);
            }
            
        }

        // At this point the username is invalid and should return just as it was passed.
        return $username;
    }

    /**
     * When creating a user account, optionally fill in preferences and such.
     * For instance, you might pull the email address or real name from the
     * external user database.
     *
     * The User object is passed by reference so it can be modified; don't
     * forget the & on your function declaration.
     *
     * NOTE: This gets the email address from PHPBB for the wiki account.
     *
     * @param User $user
     * @param $autocreate bool True if user is being autocreated on login
     * @access public
     */
    public function initUser(&$user, $autocreate = false) {
        
        if($this->getFoundConnection()){
            $connections = array($this->getFoundConnection());
        } else {
            $connections = $this->getConnections();
        }

        foreach($connections as $connection){
        
            // Connect to the database.
            $fresMySQLConnection = $this->connect($connection);

            $username   = $this->utf8($user->mName); // Convert to UTF8
            //
            $username = $this->removeConnectionUsernamePrefix($connection, $username);

            //
            // Check Database for username and email address.
            $fstrMySQLQuery = sprintf("SELECT `username_clean`, `user_email`
                              FROM `%s`
                              WHERE `username_clean` = '%s'
                              LIMIT 1", $this->getFoundConnection()->getUserTable(), mysql_real_escape_string($username, $fresMySQLConnection));


            // Query Database.
            $fresMySQLResult = mysql_query($fstrMySQLQuery, $fresMySQLConnection) or die($this->mySQLError('Unable to view external table'));

            while ($faryMySQLResult = mysql_fetch_array($fresMySQLResult)) {
                $user->mEmail = $faryMySQLResult['user_email']; // Set Email Address.
                $user->mRealName = 'I need to Update My Profile';  // Set Real Name.
                return true;
            }
        }
    }
    
    public function removeConnectionUsernamePrefix(Connection $connection, $username){
        $prefix     = $connection->getUsernamePrefix();
        $prefix     = strtolower($prefix);
        if(!empty($prefix) && strpos($username, $prefix) === 0){
            $username = substr($username, strlen($prefix));
        }
        return $username;
    }

    /**
     * Checks if the user is a member of the PHPBB group called wiki.
     *
     * @param string $username
     * @access public
     * @return bool
     * @todo Remove 2nd connection to database. For function isMemberOfWikiGroup()
     *
     */
    private function isMemberOfWikiGroup($username, Connection $connection) {
        
        $groups = $connection->getGroups();
        
        // In LocalSettings.php you can control if being a member of a wiki
        // is required or not.
        if (empty($groups)) {
            return true;
        }

        // Connect to the database.
        $fresMySQLConnection = $this->connect($connection);
        $username = $this->utf8($username); // Convert to UTF8
        $username = $this->removeConnectionUsernamePrefix($connection, $username);
        $username = mysql_real_escape_string($username, $fresMySQLConnection); // Clean username.

        foreach ($groups as $WikiGrpName) {
            /**
             *  This is a great query. It takes the username and gets the userid. Then
             *  it gets the group_id number of the the Wiki group. Last it checks if the
             *  userid and groupid are matched up. (The user is in the wiki group.)
             *
             *  Last it returns TRUE or FALSE on if the user is in the wiki group.
             */
            // Get UserId
            mysql_query('SELECT @userId := `user_id` FROM `' . $connection->getUserTable() .
                            '` WHERE `username_clean` = \'' . $username . '\';', $fresMySQLConnection) or die($this->mySQLError('Unable to get userID.'));

            // Get WikiId
            mysql_query('SELECT @wikiId := `group_id` FROM `' . $connection->getGroupTable() .
                            '` WHERE `group_name` = \'' . $WikiGrpName . '\';', $fresMySQLConnection) or die($this->mySQLError('Unable to get wikiID.'));

            // Check UserId and WikiId
            mysql_query('SELECT @isThere := COUNT( * ) FROM `' . $connection->getUserGroupTable() .
                            '` WHERE `user_id` = @userId AND `group_id` = @wikiId and `user_pending` = 0;', $fresMySQLConnection) or die($this->mySQLError('Unable to get validate user group.'));

            // Return Result.
            $fstrMySQLQuery = 'SELECT IF(@isThere > 0, \'true\', \'false\') AS `result`;';

            // Query Database.
            $fresMySQLResult = mysql_query($fstrMySQLQuery, $fresMySQLConnection) or die($this->mySQLError('Unable to view external table'));

            // Check for a true or false response.
            while ($faryMySQLResult = mysql_fetch_array($fresMySQLResult)) {
                if ($faryMySQLResult['result'] == 'true') {
                    return true; // User is in Wiki group.
                }
            }
        }
        // Hook error message.
        $GLOBALS['wgHooks']['UserLoginForm'][] = array($this, 'onUserLoginForm', $this->authError);
        return false; // User is not in Wiki group.
    }

    /**
     * This loads the phpBB files that are needed.
     *
     */
    private function loadPHPFiles($FileSet) {
        
        $GLOBALS['phpbb_root_path'] = __DIR__. '/phpbb3/'; // Path to phpBB
        $GLOBALS['phpEx'] = substr(strrchr(__FILE__, '.'), 1); // File Ext.


        
        switch ($FileSet) {
            case 'UTF8':
                // Load the phpBB file.
                require_once __DIR__. '/phpbb3/includes/utf/utf_tools.php';
                break;

            case 'phpBBLogin':
                break;
            case 'phpBBLogout':
                break;
        }
    }

    /**
     * Modify options in the login template.
     *
     * NOTE: Turned off some Template stuff here. Anyone who knows where
     * to find all the template options please let me know. I was only able
     * to find a few.
     *
     * @param UserLoginTemplate $template
     * @access public
     */
    public function modifyUITemplate(&$template, &$type) {
        $template->set('usedomain', false); // We do not want a domain name.
        $template->set('create', false); // Remove option to create new accounts from the wiki.
        $template->set('useemail', false); // Disable the mail new password box.
    }

    /**
     * This prints an error when a MySQL error is found.
     *
     * @param string $message
     * @access public
     */
    private function mySQLError($message) {
        throw new \Exception($message . '<br />' . 'MySQL Error Number: ' . mysql_errno() . '<br />' . 'MySQL Error Message: ' . mysql_error() . '<br /><br />');
    }

    /**
     * This is the hook that runs when a user logs in. This is where the
     * code to auto log-in a user to phpBB should go.
     *
     * Note: Right now it does nothing,
     *
     * @param object $user
     * @return bool
     */
    public function onUserLoginComplete(&$user) {
        // @ToDo: Add code here to auto log into the forum.
        return true;
    }

    /**
     * Here we add some text to the login screen telling the user
     * they need a phpBB account to login to the wiki.
     *
     * Note: This is a hook.
     *
     * @param string $errorMessage
     * @param object $template
     * @return bool
     */
    public function onUserLoginForm($errorMessage = false, $template) {
        $template->data['link'] = $this->loginError;

        // If there is an error message display it.
        if ($errorMessage) {
            $template->data['message'] = $errorMessage;
            $template->data['messagetype'] = 'error';
        }
        return true;
    }

    /**
     * This is the Hook that gets called when a user logs out.
     *
     * @param object $user
     */
    public function onUserLogout(&$user) {
        // User logs out of the wiki we want to log them out of the form too.
        if (!isset($this->session)) {
            return true; // If the value is not set just return true and move on.
        }
        return true;
        // @todo: Add code here to delete the session.
    }

    /**
     * Set the domain this plugin is supposed to use when authenticating.
     *
     * NOTE: We do not use this.
     *
     * @param string $domain
     * @access public
     */
    public function setDomain($domain) {
        $this->domain = $domain;
    }

    /**
     * Set the given password in the authentication database.
     * As a special case, the password may be set to null to request
     * locking the password to an unusable value, with the expectation
     * that it will be set later through a mail reset or other method.
     *
     * Return true if successful.
     *
     * NOTE: We only allow the user to change their password via phpBB.
     *
     * @param $user User object.
     * @param $password String: password.
     * @return bool
     * @access public
     */
    public function setPassword($user, $password) {
        return true;
    }

    /**
     * Return true to prevent logins that don't authenticate here from being
     * checked against the local database's password fields.
     *
     * This is just a question, and shouldn't perform any actions.
     *
     * Note: This forces a user to pass Authentication with the above
     *       function authenticate(). So if a user changes their PHPBB
     *       password, their old one will not work to log into the wiki.
     *       Wiki does not have a way to update it's password when PHPBB
     *       does. This however does not matter.
     *
     * @return bool
     * @access public
     */
    public function strict() {
        return true;
    }

    /**
     * Update user information in the external authentication database.
     * Return true if successful.
     *
     * @param $user User object.
     * @return bool
     * @access public
     */
    public function updateExternalDB($user) {
        return true;
    }

    /**
     * When a user logs in, optionally fill in preferences and such.
     * For instance, you might pull the email address or real name from the
     * external user database.
     *
     * The User object is passed by reference so it can be modified; don't
     * forget the & on your function declaration.
     *
     * NOTE: Not useing right now.
     *
     * @param User $user
     * @access public
     * @return bool
     */
    public function updateUser(&$user) {
        return true;
    }

    /**
     * Check whether there exists a user account with the given name.
     * The name will be normalized to MediaWiki's requirements, so
     * you might need to munge it (for instance, for lowercase initial
     * letters).
     *
     * NOTE: MediaWiki checks its database for the username. If it has
     *       no record of the username it then asks. "Is this really a
     *       valid username?" If not then MediaWiki fails Authentication.
     *
     * @param string $username
     * @return bool
     * @access public
     */
    public function userExists($username) {

        if($this->getFoundConnection()){
            $connections = array($this->getFoundConnection());
        } else {
            $connections = $this->getConnections();
        }

        foreach($connections as $connection){
        
            // Connect to the database.
            $fresMySQLConnection = $this->connect($connection);

            // If debug is on print the username entered by the user and the one from the datebase to the screen.
            if ($this->debug) {
                print $username . ' : ' . $this->utf8($username); // Debug
            }

            $username = $this->utf8($username); // Convert to UTF8
            $username = $this->removeConnectionUsernamePrefix($connection, $username);

            // Check Database for username.
            $fstrMySQLQuery = sprintf("SELECT `username_clean`
                              FROM `%s`
                              WHERE `username_clean` = '%s'
                              LIMIT 1", $connection->getUserTable(), mysql_real_escape_string($username, $fresMySQLConnection));

            // Query Database.
            $fresMySQLResult = mysql_query($fstrMySQLQuery, $fresMySQLConnection) or die($this->mySQLError('Unable to view external table'));

            while ($faryMySQLResult = mysql_fetch_array($fresMySQLResult)) {

                // If debug is on print the username entered by the user and the one from the datebase to the screen.
                if ($this->debug) {
                    print $username . ' : ' . $faryMySQLResult['username_clean']; // Debug
                }

                // Double check match.
                if ($username == $faryMySQLResult['username_clean']) {
                    return true; // Pass
                }
            }
            
        }
        
        return false; // Fail
    }

    /**
     * Cleans a username using PHPBB functions
     *
     * @param string $username
     * @return string
     */
    private function utf8($username) {
        $this->loadPHPFiles('UTF8'); // Load files needed to clean username.
        error_reporting(E_ALL ^ E_NOTICE); // remove notices because phpBB does not use include once.
        $username = utf8_clean_string($username);
        error_reporting(E_ALL);
        return $username;
    }

    /**
     * Check to see if the specific domain is a valid domain.
     *
     * @param string $domain
     * @return bool
     * @access public
     */
    public function validDomain($domain) {
        return true;
    }

}