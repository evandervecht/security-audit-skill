<?php
// SA-DRUPAL-01: db_query with string interpolation (VULNERABLE)
function mymodule_get_user($username) {
    $result = db_query("SELECT * FROM {users} WHERE name = '$username'");
    return $result->fetchObject();
}
