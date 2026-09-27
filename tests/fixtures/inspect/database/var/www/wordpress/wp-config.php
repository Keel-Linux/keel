<?php
// The two halves of the database section on one machine: the server is
// installed here (usr/sbin/mariadbd) and this is what uses it. The address
// is a literal, never localhost.
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'hunter2-NEVER-READ' );
define( 'DB_HOST', '[::1]:3306' );
define( 'DB_CHARSET', 'utf8' );
$table_prefix = 'wp_';
