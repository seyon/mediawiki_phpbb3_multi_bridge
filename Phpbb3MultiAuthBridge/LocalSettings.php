<?php

// PHPBB User Database Plugin. (Requires MySQL Database)
require_once './extensions/Phpbb3MultiAuthBridge/classloader.php';

$wgAuth = new Seyon\Phpbb3MultiAuthBridge\MultiAuthBridge();
$wgAuth->setLoginErrorMessage('<b>You need a phpBB account to login.</b><br />');
$wgAuth->setAuthErrorMessage('You are not a member of the required phpBB group.');
//$wgAuth->addPHPBBSystem(
//        $wgAuth_Config['MySQL_Host'],
//        $wgAuth_Config['MySQL_Username'],
//        $wgAuth_Config['MySQL_Password'],
//        $wgAuth_Config['MySQL_Database'],
//        'phpbb_',
//        array('wiki'), // phpbb groups
//        '' // prefix for users, you need different prefixes for each phpbbsystem because two or more system can have the same usernames
//);
// repeat this for more systems...