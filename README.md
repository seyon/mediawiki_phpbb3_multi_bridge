mediawiki PHPBB3 Multi Auth Bridge
==================================


# Installation

## Step 1

Copy the Folder Phpbb3MultiAuthBridge into your wiki "extensions" directory.

## Step 2

Copy the content of "Phpbb3MultiAuthBridge/LocalSettings.php" into your own LocalSettings.php file (insert at end of file)

# Add a PHPBB3 System

Insert this at the end of your LocalSettings.php file for each phpbb3 system

    $wgAuth->addPHPBBSystem(
            'DATABASE HOST',
            'DATABASE_USER',
            'DATABASE_PASSWORD',
            'DATABASE_DATABASENAME',
            'phpbb_', // prefix of your phpbb tables
            array(), // phpbb groups | empty = all users have acces | array = only user with this group
            '' // prefix for users, you need different prefixes for each phpbbsystem because two or more system can have the same usernames
    );
