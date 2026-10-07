<?php
// SA-WP-01: SQL query without $wpdb->prepare() (VULNERABLE)
function get_user_data($user_id) {
    global $wpdb;
    $results = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}users WHERE ID = $user_id");
    return $results;
}
