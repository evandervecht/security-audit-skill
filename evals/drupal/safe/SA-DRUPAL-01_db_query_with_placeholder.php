<?php
// SA-DRUPAL-01: db_query with placeholder (SAFE)
function mymodule_get_user($username) {
    $result = db_query("SELECT * FROM {users} WHERE name = :name", array(
        ':name' => $username,
    ));
    return $result->fetchObject();
}
