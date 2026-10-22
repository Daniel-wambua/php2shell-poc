<?php
$page = $_GET['page'] ?? '';
if ($page !== '') {
    include($page);
}
